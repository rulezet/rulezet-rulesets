rule DITEKSHEN_INDICATOR_SUSPICIOUS_Antivm_UNK01: FILE {
  meta:
    description = "Detects memory artifacts referencing specific combination of anti-VM checks"
    author      = "ditekSHen"
    id          = "57344ff4-5204-535a-a128-0f9f7eb7c760"
    date        = "2024-06-08"
    modified    = "2024-06-08"
    reference   = "https://github.com/ditekshen/detection"
    source_url  = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/yara/indicator_suspicious.yar#L1955-L1977"
    license_url = "https://github.com/ditekshen/detection/blob/2ddbbe14eea1f342bca2cfd09a643a40ae2fcaf6/LICENSE.txt"
    logic_hash  = "c34b23e26df0d33d60cf87e406dfbc90f9fd6df0da4415b6622d477cf38bc024"
    score       = 40
    quality     = 45
    tags        = "FILE"
    importance  = 20

  strings:
    $s1  = "vmci.s" fullword ascii wide
    $s2  = "vmmemc" fullword ascii wide
    $s3  = "qemu-ga.exe" fullword ascii wide
    $s4  = "qga.exe" fullword ascii wide
    $s5  = "windanr.exe" fullword ascii wide
    $s6  = "vboxservice.exe" fullword ascii wide
    $s7  = "vboxtray.exe" fullword ascii wide
    $s8  = "vmtoolsd.exe" fullword ascii wide
    $s9  = "prl_tools.exe" fullword ascii wide
    $s10 = "7869.vmt" fullword ascii wide
    $s11 = "qemu" fullword ascii wide
    $s12 = "virtio" fullword ascii wide
    $s13 = "vmware" fullword ascii wide
    $s14 = "vbox" fullword ascii wide
    $s15 = "%systemroot%\\system32\\ntdll.dll" fullword ascii wide

  condition:
    uint16(0) == 0x5a4d and all of them
}