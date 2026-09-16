rule j2321_29274286cd3b0b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.29274286cd3b0b32"
    cluster      = "j2321.29274286cd3b0b32"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['4d7a469a284a7b25df27536de1e96725','6f26096dd00c0da5c36aa7706c35354d','e4cdc18683db99ca433f466e35cc2834']"

  strings:
    $hex_string = { 12 b5 37 a0 cf 52 9a 1e ef 95 71 51 66 b9 85 14 e1 e6 74 dc 48 3f 0b eb 66 92 4f 45 b0 32 bd 88 96 19 ac 6c 3c a7 20 8c 7a bf 06 8a 6a 8c c6 6b 83 c0 a8 53 27 c0 d4 13 d8 61 f7 75 9c d9 6f 38 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}