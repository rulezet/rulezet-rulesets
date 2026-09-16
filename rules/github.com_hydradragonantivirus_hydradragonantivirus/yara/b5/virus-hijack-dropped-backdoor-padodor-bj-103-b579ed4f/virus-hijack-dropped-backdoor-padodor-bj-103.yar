rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_103 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_103.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a17096e1f8e3a47c0a0e221a58f762787433c0248f6efeaf5eaf406380dbf95"

  strings:
    $s1 = "flOfwe]{qfOsuh[b~d`DPFzHD]UpKGmHUZUdW[{BL]_BPZ`HLuL_REfUG[UePF~TGglPr[fDGZz'eEfECE\\TG[FADE`IG)ZHD]~FPLUjKJ{HQFoS~~`IFF~T~j|UPLg" ascii
    $s2 = "flOfwe]{qfOsuh[b~d`DPFzHD]UpKGmHUZUdW[{BL]_BPZ`HLuL_REfUG[UePF~TGglPr[fDGZz'eEfECE\\TG[FADE`IG)ZHD]~FPLUjKJ{HQFoS~~`IFF~T~j|UPLg" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}