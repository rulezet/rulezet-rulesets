rule k2321_09695822d5bb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.09695822d5bb1912"
    cluster      = "k2321.09695822d5bb1912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vbkrypt vobfus wbna"
    md5_hashes   = "['50a758b49c751e389e2d8d20e5dcae3d','572d0ea8703a4d94679af17b1a2a760f','b436883eacaf4b4117f19f8f5bcc05c6']"

  strings:
    $hex_string = { 41 a8 2e b7 29 18 f7 3f f6 6d c3 71 64 5a 0d d3 01 8c 0f 16 75 9c 9b dc 8b ee 46 ca bc 4d 85 0b d1 e7 b0 9e 9e 89 e3 79 9a 61 ae 8a fc e5 68 d4 31 d6 49 86 9d 57 c5 b5 60 94 d6 5b 23 2b a5 aa }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}