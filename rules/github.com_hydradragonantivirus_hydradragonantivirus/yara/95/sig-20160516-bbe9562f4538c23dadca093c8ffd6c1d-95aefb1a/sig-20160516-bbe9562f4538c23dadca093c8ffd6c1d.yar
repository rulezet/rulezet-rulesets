rule sig_20160516_bbe9562f4538c23dadca093c8ffd6c1d {
  meta:
    description = "datamaliciousorder - file 20160516_bbe9562f4538c23dadca093c8ffd6c1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21e414d1e9c0a2c4a2ea5678267e2289a4d0f222422464feceed6fedd7f4ff9e"

  strings:
    $s1 = "var o1g3='vzcrijaze12kro4wc1 yudwgtxdwknaqfm2eyy1lgjbffryhhmyk3bjipzsmtjrtbbsu4lwabplafwopecfd=jmb2o\\'vmefftfp1nucbyxsvnfmgcvij" ascii
    $s2 = "Object(\"VBS\"+\"cript\"+\".RegE\"+\"xp\");   bcd2sdyoi=r4+\"v\"+\"al\";   WScript.lister=5;   bcd2sdyoi=\"\"+\"s\";   ww=232323" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}