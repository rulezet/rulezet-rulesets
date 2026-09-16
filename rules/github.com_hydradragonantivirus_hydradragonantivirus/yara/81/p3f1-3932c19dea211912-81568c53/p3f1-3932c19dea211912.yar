rule p3f1_3932c19dea211912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3f1.3932c19dea211912"
    cluster      = "p3f1.3932c19dea211912"
    cluster_size = "4"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "riskware skymobi androidos"
    md5_hashes   = "['3ca252f85fe8407bb984d5bbe3b2eaa3','49d80c985c0b1a43e60d1364ed31c5d2','e70287a10a4efbafe58e9e6fd77b8e7e']"

  strings:
    $hex_string = { e3 ed f5 a4 03 f2 6f 13 b8 64 35 a6 f3 ee 0e e6 20 6d b5 ab ef b2 0f f7 96 dd 74 55 e0 77 b1 3d ce 3b 97 58 d8 5f 05 f6 4a cc e8 c1 3e 2e 70 16 5a d5 5c 53 88 23 5b 99 61 d3 1c b7 3a b0 5d 69 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}