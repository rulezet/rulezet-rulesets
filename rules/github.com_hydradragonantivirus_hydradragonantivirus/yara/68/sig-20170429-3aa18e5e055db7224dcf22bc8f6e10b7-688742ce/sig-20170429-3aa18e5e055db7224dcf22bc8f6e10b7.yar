rule sig_20170429_3aa18e5e055db7224dcf22bc8f6e10b7 {
  meta:
    description = "datamaliciousorder - file 20170429_3aa18e5e055db7224dcf22bc8f6e10b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "441ee54510296aabc225c1120eec404809856216d2d02b38d22f44d110d4ad5f"

  strings:
    $s1 = "if ((yKUfWFEjkBehbwTcu != 60144/83056*sSOYtpHjzGdgTaNrqw) && (yKUfWFEjkBehbwTcu != 91648/83056*sSOYtpHjzGdgTaNrqw) && (VKzMUugEJ" ascii
    $s2 = "GmpaslXfy() == false)) { ebwlMJmUrQAkqKa += sXzQxaFjEKuwtVSBT (yKUfWFEjkBehbwTcu); }}" fullword ascii
    $s3 = "function rPAvfBpxFngNaoT(imkAVvDOXYawHdPNFjT, uXxvNhSgoYEKbjJ) { " fullword ascii
    $s4 = "return imkAVvDOXYawHdPNFjT.replace(RegExp(uXxvNhSgoYEKbjJ, \"g\"), \"\"); }" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}