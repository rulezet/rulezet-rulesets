rule sig_20160525_08159a8e4482e4802d9526281ae86cbe {
  meta:
    description = "datamaliciousorder - file 20160525_08159a8e4482e4802d9526281ae86cbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "508c864bb507ff37e3e279b2815bd0e090ca76ee0a8af32fd0e1c7165bcac26d"

  strings:
    $s1 = "rav\\n;\"f4x\\\\56x\\\\t\" = rerednerl rav\\n;\"cea6x\\\\b\" = iml rav\\n;\"47x\\\\\" = eixodm rav\\n;\"44x\\\\A\" = gsmm rav\\n" ascii
    $s2 = "dare(keppele+me+dnenoisilloce + suidarelcitrape ,gsme + eixode+imd+rerednerd+cthd + tsilslianbmuhtod+ssorcad + sdnetd+))(};modna" ascii
    $s3 = "imi[ = ssorca rav\\n\\n;))(};cthi nruter{)(reredneri noitcnuf( + tsilslianbmuhtoi + eixoda = modnara rav\\n;ssorcai + sdneti + d" ascii
    $s4 = " modnare rav\\n;\"ce2x\\\\\" = deerde rav\\n;\".d6x\\\\o\" = sdnete rav\\n;\"57x\\\\n/xd6x\\\\\" = ssorcae rav\\n;\"f327x\\\\\" " ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}