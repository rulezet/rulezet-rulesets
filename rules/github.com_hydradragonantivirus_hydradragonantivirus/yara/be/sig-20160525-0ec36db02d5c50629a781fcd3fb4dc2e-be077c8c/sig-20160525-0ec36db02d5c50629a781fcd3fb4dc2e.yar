rule sig_20160525_0ec36db02d5c50629a781fcd3fb4dc2e {
  meta:
    description = "datamaliciousorder - file 20160525_0ec36db02d5c50629a781fcd3fb4dc2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9193fd8819f37cbc96d977ae6bc2548d2726b8b7c4942e04fd0a8fc756ca1085"

  strings:
    $s1 = "oda rav\\n;)))(};ssorcag nruter{)(tsilslianbmuhtog noitcnuf( + sdnetg(sgnirtStnemnorivnEdnapxE.dnenoisillocb = modnar rav\\n;)de" ascii
    $s2 = "n;\"ta26x\\\\e2x\\\\\" = tsilslianbmuhton rav\\n;\"taer34x\\\\\" = rerednern rav\\n;\"a6x\\\\bOe\" = imn rav\\n;\"c56x\\\\\" = e" ascii
    $s3 = "darn + mn + dnenoisillocn[eixodb    \\n;))rerednera(m(]dnenoisillocu + suidarelcitrapu + ))(};gsmu nruter{)(mu noitcnuf([eixodb " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}