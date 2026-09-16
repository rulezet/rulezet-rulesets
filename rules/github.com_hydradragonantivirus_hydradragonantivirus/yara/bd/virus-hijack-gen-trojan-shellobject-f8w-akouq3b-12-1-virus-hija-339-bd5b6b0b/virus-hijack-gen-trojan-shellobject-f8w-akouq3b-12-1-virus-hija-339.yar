import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_12_1_Virus_Hija_339 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00803b2a9624ab755ca403c3abbf03d7dc3ac396a7c3fbcfb7471d7281cdf9d0"
    hash2       = "2b6862758d7e1fa0b613e8ef792cc1c36a85e6c0806094fb9cbe5c36045e1dbf"

  strings:
    $s1  = "* use the software for commercial software hosting servic" fullword wide
    $s2  = "The software is licensed \"as - is.\" You bear the risk of using it.Sysinternals gives no express warranties, guarantees or cond" wide
    $s3  = "The software is licensed \"as - is.\" You bear the risk of using it.Sysinternals gives no express warranties, guarantees or cond" wide
    $s4  = "%s -e \"load('dotty.lefty');%sdotty.init();dotty.cre" fullword ascii
    $s5  = "%s -e \"load('dotty.lefty');dotty.protogt." fullword ascii
    $s6  = "* claims for breach of contract, breach of warranty, guarantee or cond" fullword wide
    $s7  = "* work around any technical limitations in the soft" fullword wide
    $s8  = "ficier de droits additionnels en vertu du droit local sur la protection dues consommateurs, que ce contrat ne peut modifier. La " wide
    $s9  = "Visual C++ CRT: Not enough memory to complete call to strerro" fullword ascii
    $s10 = " aucune indemnisation pour les autres dommages, y compris" fullword wide
    $s11 = "*and support service" fullword wide
    $s12 = "\\pard\\b Please note: As this software" fullword ascii
    $s13 = "\\pard\\fi-363\\li720\\sb120\\sa120\\tx720\\'b7\\tab les r\\'e9clamations au titre de viola" fullword ascii
    $s14 = "Make sure that y" fullword ascii
    $s15 = "Could not" fullword wide
    $s16 = "*rent, lease or lend the softwar" fullword wide
    $s17 = "bad except" fullword ascii
    $s18 = "Because this software is \"as is, \" we may not prov" fullword wide
    $s19 = "The certificate or one of the certific" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "539502771da573641ecc7f6497e39f8f" and (8 of them)
    ) or (all of them)
}