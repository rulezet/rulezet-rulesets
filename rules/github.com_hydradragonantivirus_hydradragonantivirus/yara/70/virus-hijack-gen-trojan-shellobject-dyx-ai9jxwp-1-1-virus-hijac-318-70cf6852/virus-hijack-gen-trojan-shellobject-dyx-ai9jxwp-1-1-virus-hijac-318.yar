rule _Virus_Hijack_Gen_Trojan_ShellObject_dyX_ai9jxwp_1_1_Virus_Hijac_318 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.dyX@ai9jxwp_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_104_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_105_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_106_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_85_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a98a2728de2eea7db2532bbf8f79c6ec1dc6a120fe07103807b03434acedd84"
    hash2       = "1402d55ebe79764aa6b500d90065bfe6cac3be6e4b121d503aade48ba3beab58"
    hash3       = "b855bce10c0efd4998e88e95f6bfa4a2f6088c7c5b1befadcff2bb2045f159c7"
    hash4       = "7c9e89c6d6226a5bbb0a4027211b230c847f293a3162d91841125bf0ad032ad9"
    hash5       = "b1b1a9fb160b36ba22f829ffbd02988ba821a5649910c7f2cc9b2264e0dc12f9"
    hash6       = "00803b2a9624ab755ca403c3abbf03d7dc3ac396a7c3fbcfb7471d7281cdf9d0"
    hash7       = "2b6862758d7e1fa0b613e8ef792cc1c36a85e6c0806094fb9cbe5c36045e1dbf"

  strings:
    $s1  = "[%s] ShellExecute can not run because Installer Signature verification failed" fullword wide
    $s2  = "[%s] DeleteFile fail - (%d)%s" fullword wide
    $s3  = "[%s] MoveFile fail - (%d)%s" fullword wide
    $s4  = "C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\VC\\Tools\\MSVC\\14.24.28314\\atlmfc\\include\\afxwin1.inl" fullword wide
    $s5  = "[SamsungDeX] [%s] UpdateClient is already running." fullword wide
    $s6  = "SRenderingCore::GetHDC ## hDC is NULL" fullword wide
    $s7  = "[SamsungDeX] [%s] Parameter is empty." fullword wide
    $s8  = "TrackMouseEvent() returns FALSE. (ERROR CODE: 0x%08x)" fullword wide
    $s9  = "----cairo_create is Fail (%d)----" fullword wide
    $s10 = "update Panel" fullword wide
    $s11 = "Modal Popup" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}