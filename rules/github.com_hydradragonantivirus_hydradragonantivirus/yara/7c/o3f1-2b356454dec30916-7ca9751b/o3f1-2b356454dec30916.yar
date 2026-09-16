rule o3f1_2b356454dec30916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f1.2b356454dec30916"
    cluster      = "o3f1.2b356454dec30916"
    cluster_size = "60"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androidos risktool skymobi"
    md5_hashes   = "['08fda2b10d47d7c87528b7fd62fc9085','0aabba19f8b6d81c09014bd0f680ad31','48c27e2e3fd9e10786d98c55227900e6']"

  strings:
    $hex_string = { 16 7a 7b 1b a6 8e bc 2a 69 52 28 f2 24 97 85 13 a2 9f db 58 ae 1c 9a bd 36 da 6b 57 06 23 8d 9e cf f9 0a f5 09 f1 95 62 87 dc 51 e0 c8 8f f6 e5 c6 e9 be a0 f4 e2 a4 2c 44 08 18 94 d3 15 ee 14 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}