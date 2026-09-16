rule _20160802_6f8a3b3943ecf61763c5cd034903a47d_20160802_bbe19f018fdf_517 {
  meta:
    description = "datamaliciousorder - from files 20160802_6f8a3b3943ecf61763c5cd034903a47d.js, 20160802_bbe19f018fdffe668a3aae64b421f965.js, 20160802_c49dd44cbc2a094f8caf7144fe069ef6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c33ba1bf78e59749625f33f9e1c7655dbc435674e25ca3599b97972646230e4"
    hash2       = "25bbec6f1a437208625ba7b78d87fae5bafdfb17a9ecc55a647cc7d589f3ea48"
    hash3       = "183e7ac6d588d085a408dc063d459d33d8a99d01cc5d983557602f29285bf2d1"

  strings:
    $s1 = "4]=19363 - 9731;\\x0d\\nPa\\x37[255]=16\\x30;\\r\\n\\t\\r\\n\\tvar D\\x71=new Array(\\x29;\\r\\n\\tva\\x72 Og=\"\";\\r\\n\\tvar" ascii
    $s2 = "t\\t\\x7bvar E\\x4eo=\\x53\\x71[EFq7]\\x3b}\\r\\n\\t\\tHFz\\x5b\\x28function Gk(){return RUn9;}()) + JVi](ENo);\\r\\n\\x09};\\r" ascii
    $s3 = "\\r\\n};\\r\\n\\r\\n\\r\\nfu\\x6ection NFc(Tf0\\x29\\r\\n{   \\r\\x0avar Sq=new Array()\\x3b\\x0d\\n\\t\\r\\nSq\\x5b2071 - 1872]" ascii
    $s4 = "q[-6592 + 6770]=253;\\r\\nSq[96\\x332]=254;\\x0d\\x0aSq[160]=255;\\r\\n\\t\\r\\n\\tva\\x72 \\x48\\x46z=new Array(\\x29;\\r\\n\\t" ascii
    $s5 = "ENo < 128) \\r\\x0a\\t\\x09\\t{E\\x46q7=ENo;}\\r\\n\\t\\telse \\r\\n\\t\\t\\t{E\\x46q7=Pa7[ENo];\\x7d\\r\\n\\t\\tDq.push(String[" ascii

  condition:
    (uint16(0) == 0x200a and (all of them)
    ) or (all of them)
}