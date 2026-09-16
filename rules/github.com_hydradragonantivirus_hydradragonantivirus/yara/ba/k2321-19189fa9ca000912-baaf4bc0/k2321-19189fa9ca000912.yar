rule k2321_19189fa9ca000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.19189fa9ca000912"
    cluster      = "k2321.19189fa9ca000912"
    cluster_size = "34"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nimnul vjadtre small"
    md5_hashes   = "['1397ba78fd83ba785f8b806b71d77ac3','25d082dfac164cf754ec06c5329e4700','7ca72f6488363e0d93e3374e4b559de4']"

  strings:
    $hex_string = { a5 c2 29 72 8a 00 a7 b7 1f 2f e1 a8 d8 76 7c 24 d2 2b 28 32 3c 56 f9 cc b6 0a cd b4 be 66 af db ba 9e 78 8d 10 4c 0f c5 71 bd 0c b3 91 a1 26 f3 f0 7c d7 e6 15 c6 ee 99 78 0e 93 42 45 55 ff 22 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}