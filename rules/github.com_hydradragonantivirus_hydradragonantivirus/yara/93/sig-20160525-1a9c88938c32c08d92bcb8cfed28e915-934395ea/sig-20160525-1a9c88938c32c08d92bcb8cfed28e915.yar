rule sig_20160525_1a9c88938c32c08d92bcb8cfed28e915 {
  meta:
    description = "datamaliciousorder - file 20160525_1a9c88938c32c08d92bcb8cfed28e915.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc4c0c22c936e32632beeda56ac7141d4d849fa23d69647f840158155659b708"

  strings:
    $s1 = "rav\\n;\"f4x\\\\56x\\\\t\" = rerednerl rav\\n;\"cea6x\\\\b\" = iml rav\\n;\"47x\\\\\" = eixodm rav\\n;\"44x\\\\A\" = gsmm rav\\n" ascii
    $s2 = "dare(keppele+me+dnenoisilloce + suidarelcitrape ,gsme + eixode+imd+rerednerd+cthd + tsilslianbmuhtod+ssorcad + sdnetd+))(};modna" ascii
    $s3 = "imi[ = ssorca rav\\n\\n;))(};cthi nruter{)(reredneri noitcnuf( + tsilslianbmuhtoi + eixoda = modnara rav\\n;ssorcai + sdneti + d" ascii
    $s4 = " modnare rav\\n;\"ce2x\\\\\" = deerde rav\\n;\".d6x\\\\o\" = sdnete rav\\n;\"57x\\\\n/xd6x\\\\\" = ssorcae rav\\n;\"f327x\\\\\" " ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}