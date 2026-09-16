rule sig_20160517_11535c049c7805cfc02b3a3a2c7c3c95 {
  meta:
    description = "datamaliciousorder - file 20160517_11535c049c7805cfc02b3a3a2c7c3c95.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ee9f80346b97e1e3b88475b0a7223d31eced76e125810f47d59a4375db7d1a4"

  strings:
    $s1 = "var bv4='vw4s2ralcqvurlnoqy wopplmxuwymxsnpvupqmxjnqpgtgbjtttdkcpq3hftsdakcrphthd=j3tlm\\'bawbltutfv1canrvznljdbyiowgcdfwufgfuzr" ascii
    $s2 = "ateObject(\"VBS\"+\"cript\"+\".RegE\"+\"xp\");   us1cblm3xq=r4+\"v\"+\"al\";   WScript.lister=5;   us1cblm3xq=\"\"+\"s\";   ww=2" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}