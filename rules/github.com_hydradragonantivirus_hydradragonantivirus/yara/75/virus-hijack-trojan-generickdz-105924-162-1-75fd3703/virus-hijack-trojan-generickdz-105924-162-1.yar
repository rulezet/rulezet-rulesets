rule Virus_Hijack_Trojan_GenericKDZ_105924_162_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_162_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e7545d14df7b618b3b1bc24321780c164a0a14d3600dbac0f91afbce1a2f9f4"

  strings:
    $x1 = "powershell -exec bypass -f " fullword ascii
    $s2 = "powershell -exec bypass \"" fullword ascii
    $s3 = "function bd($in){$out = [System.Convert]::FromBase64String($in);return [System.Text.Encoding]::UTF8.GetString($out);}" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}