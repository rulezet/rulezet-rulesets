rule Virus_Hijack_Gen_Trojan_ShellObject_DCZ_aSNPrTf {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DCZ@aSNPrTf.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b2be7e4715450069bd5e039795eae9cfca7bc4c15dc17a15e7a7d854ead05ea"

  strings:
    $s1 = "access the documentation online at http://oracle.com/contracts. Se" fullword ascii
    $s2 = "$<aTrY%Cpx-" fullword ascii
    $s3 = "LesS>0pDrY<*6r]rY<Y\")uDl-y@)d\"C9;mY8{ F-5uUq~'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}