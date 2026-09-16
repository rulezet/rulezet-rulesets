rule sig_20160517_9753a41e9ba8ac0fcc2327085bfb0b77 {
  meta:
    description = "datamaliciousorder - file 20160517_9753a41e9ba8ac0fcc2327085bfb0b77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c074f0220bce0c9ea81203b288fba380d3c3eb7f291df19ad35b847301ad268"

  strings:
    $s1 = "var qla='vt1eybaeuyyyrnxffn gerfrexadqafn13dsxylstk4gmewktz3imiul3qri4tymqomknpuvfwfha3=d3pay\\'li1lytll24ccumb1dnssvjmizuw3yfzy" ascii
    $s2 = "Object(\"VBS\"+\"cript\"+\".RegE\"+\"xp\");   sbcvunyr=r4+\"v\"+\"al\";   WScript.lister=5;   sbcvunyr=\"\"+\"s\";   ww=232323; " ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}