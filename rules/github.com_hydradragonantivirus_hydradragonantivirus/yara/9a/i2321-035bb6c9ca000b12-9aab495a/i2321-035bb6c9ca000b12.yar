rule i2321_035bb6c9ca000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.035bb6c9ca000b12"
    cluster      = "i2321.035bb6c9ca000b12"
    cluster_size = "4"
    filetype     = "gzip compressed data"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmicduke backdoor razy"
    md5_hashes   = "['1347f23880eee38ecaf86b2d8ee8a908','57b8a1495a20b3e8ff2690c15e9c2747','aa7762daeec2be396a470e1b718a3467']"

  strings:
    $hex_string = { f9 17 cb b5 23 b5 da fc 4c 78 76 6b 6d a1 d9 a8 55 ea b1 e4 ed 4e c9 b1 46 a5 12 c2 37 72 cf 54 9a 47 e7 cf 9d 2b d7 67 47 e7 ea 95 52 38 3e 3c fe ec f0 e8 81 a7 b2 8e c3 81 ae af 2e 9c 6f cc }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}