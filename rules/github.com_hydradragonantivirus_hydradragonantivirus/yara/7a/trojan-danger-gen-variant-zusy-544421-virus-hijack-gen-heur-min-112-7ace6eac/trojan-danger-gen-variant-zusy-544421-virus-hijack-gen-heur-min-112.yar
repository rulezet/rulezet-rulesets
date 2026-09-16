rule _Trojan_Danger_Gen_Variant_Zusy_544421_Virus_Hijack_Gen_Heur_Min_112 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Gen.Variant.Zusy.544421.vir, Virus.Hijack_Gen.Heur.Mint.Zard.30_12_1.vir, Virus.Hijack_Gen.Heur.Mint.Zard.30_13_1.vir, Virus.Hijack_Gen.Heur.Mint.Zard.30_14_1.vir, Virus.Hijack_Gen.Heur.Mint.Zard.30_15_1.vir, Virus.Hijack_Gen.Heur.Mint.Zard.30_16_1.vir, Virus.Hijack_Gen.Heur.Mint.Zard.30_17_1.vir, Virus.Hijack_Gen.Heur.Mint.Zard.30_18_1.vir, Virus.Hijack_Gen.Heur.Mint.Zard.30_19_1.vir, Virus.Hijack_Gen.Heur.Mint.Zard.30_20_1.vir, Virus.Hijack_Gen.Heur.Mint.Zard.30_21_1.vir, Virus.Hijack_Gen.Heur.Mint.Zard.30_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84395b7e8defd5bbf5cd1be5886b59fae313839aa8ccff49c305b9c933ebe386"
    hash2       = "1614748600fc45024180e432464c8cca5fadff666f1db73b301d25b4581dcfc4"
    hash3       = "af956b38f535fdd0348e2677be9016d86166d50baf3d624d368c7ff9ba7bc5ac"
    hash4       = "578ab9e5f67e9151dcafd5356e5f3728b1503ee0ee825fc70b92a798236d5e6a"
    hash5       = "eb4de522357a1fada54120d47cf544cd04a14a3f7d493e5b1b84e595b1e211c2"
    hash6       = "1f021a7f6ef2beee88906a2b78e6c009d2698d843f687f6856f85e6dd820d162"
    hash7       = "501b39adb00a03cc674b17d810d4583e39d8959e3e00695d39dbe232f0cfdacf"
    hash8       = "b239845d33c0c990a7c875b4f02aade2e9a7125b7cb27cfa90aee327702e42c3"
    hash9       = "b3e7f0fe213fbaecfc550dbb947aa168e3ee9d223b6f09b901abce748d5bce23"
    hash10      = "96bd97d2504cff3cc4f9cc228f10588512304ea6f32ba528751f4632bdab00d0"
    hash11      = "635f6b9897237fec8fc57b2f443063ca126344474813be603819c5b615cdfb04"
    hash12      = "d2dcddc656cdc4ec72dc26a305ee9d3baa10499b516bbaa3818289a6eae732f5"

  strings:
    $s1  = "v ue otic oiyaoo" fullword ascii
    $s2  = "object teamexpect ship born him trianglenaturalproper" fullword wide
    $s3  = "knewtotal money large spoke westsuccessline" fullword wide
    $s4  = "I oo DTtePpte biy s Eatr pLeW o" fullword ascii
    $s5  = ".h Riot , " fullword ascii
    $s6  = "tOAdioenmrYuiso f yopid s od nete h,nIcb" fullword ascii
    $s7  = "Tore,Lil. estnfsePiscdhI Tuno  ttioe  sn c i tiIs  lYnxynnEiB saany.cyrt aneL eTFCho" fullword ascii
    $s8  = " hP\"rv KuOr tara" fullword ascii
    $s9  = "Vole oeitnitc`twtdrF" fullword ascii
    $s10 = "i cLseedhu m fTmor hEwt e m tiec  toreymI h" fullword ascii
    $s11 = " cairomm is free software: you ca" fullword ascii
    $s12 = " This file is part of cairomm." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}