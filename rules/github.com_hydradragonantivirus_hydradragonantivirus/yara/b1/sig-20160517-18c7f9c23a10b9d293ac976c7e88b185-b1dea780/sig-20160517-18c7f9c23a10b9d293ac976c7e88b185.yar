rule sig_20160517_18c7f9c23a10b9d293ac976c7e88b185 {
  meta:
    description = "datamaliciousorder - file 20160517_18c7f9c23a10b9d293ac976c7e88b185.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43470d174d421a9eb5218d4ab7121a9cb91f8c335cba7a0d09f675ab124d6dab"

  strings:
    $s1 = "var qla='vt1eybaeuyyyrnxffn gerfrexadqafn13dsxylstk4gmewktz3imiul3qri4tymqomknpuvfwfha3=d3pay\\'li1lytll24ccumb1dnssvjmizuw3yfzy" ascii
    $s2 = "Object(\"VBS\"+\"cript\"+\".RegE\"+\"xp\");   sbcvunyr=r4+\"v\"+\"al\";   WScript.lister=5;   sbcvunyr=\"\"+\"s\";   ww=232323; " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}