rule sig_20160517_032cd435f0d219d50465717ee0271182 {
  meta:
    description = "datamaliciousorder - file 20160517_032cd435f0d219d50465717ee0271182.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e50c6c20c2e0deb16e0679adb40a8a75d4833ccddd7e082ce2faac9db9f34161"

  strings:
    $s1 = "var cfchb='vqov1gaqkfjnrviwyi enmblxaoyxz3qdwthkiyzkywa4jpndkezxdgisuyxzname2esffi31a22rlsf2pjq=fkych\\'boa1mttgropcbaz3mncun4li" ascii
    $s2 = "BS\"+\"cript\"+\".RegE\"+\"xp\");   ikqycshp1r=r4+\"v\"+\"al\";   WScript.lister=5;   ikqycshp1r=\"\"+\"s\";   ww=232323;   }cat" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}