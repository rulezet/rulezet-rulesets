rule sig_20160314_3cc2add0da156b6674325d3f65bd4656 {
  meta:
    description = "datamaliciousorder - file 20160314_3cc2add0da156b6674325d3f65bd4656.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4824107b89d2796e859304e792838e885f761934f5a0436959145b96e69bb311"

  strings:
    $s1 = "while (HcZcxyYK.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "return NTnryYwMaGKUcgM + LwEf + CJVemVaO + EmjtCbLsVGDhHD + OpSzWHFbObhgC + yorbFWIuLGOC + lDyLIPQnPKyuco" fullword ascii
    $s3 = "HcZcxyYK.open(ECqDipX, TMFDvlZc + maj + MNDgjNT + etGDSMgteMc + RMzRZLgKu + JoLDnJBVYrkXfMG + dFGrerPloByRHNN + lQTVTathyWZlY + " ascii
    $s4 = "function RlinuHnuS(fname)" fullword ascii
    $s5 = "function qfIUd(n)" fullword ascii
    $s6 = "var UfdKnaE = new Date();" fullword ascii
    $s7 = "aeIAV, false);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}