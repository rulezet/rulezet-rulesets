rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_685_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_685_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "417119f87db275829633acdb584f287c367d81a57de072e0775c89dc6527bbc8"

  strings:
    $s1 = "flOfwe]{qfOsuh[b~d`DPFzHD]UpKGmHUZUdW[{BL]_BPZ`HLuL_REfUG[UePF~TGglPr[fDGZz'eEfECE\\TG[FADE`IG)ZHD]~FPLUjKJ{HQFoS~~`IFF~T~j|UPLg" ascii
    $s2 = "flOfwe]{qfOsuh[b~d`DPFzHD]UpKGmHUZUdW[{BL]_BPZ`HLuL_REfUG[UePF~TGglPr[fDGZz'eEfECE\\TG[FADE`IG)ZHD]~FPLUjKJ{HQFoS~~`IFF~T~j|UPLg" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}