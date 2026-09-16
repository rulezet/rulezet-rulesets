rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f01016040ff42857306570eb0985e7936976b602f10795212e26e63bb572692"

  strings:
    $s1 = "7or service that is subject to a discount or a pr" fullword ascii
    $s2 = "C;+>/??WAKY7C98>2.Y0C8<##>?WAKY:C8)%(%-1AKY\"C8-%\"; WAKY" fullword ascii
    $s3 = ">,.6\"5c{/ib{{d>plAn*$$'?y1*+2/?w;.(8#($7jcn*uzK?\"/(->.%y/ibYr2wxzlk|\"aftiAaw}A" fullword ascii
    $s4 = "C&8;-$:WAKY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}