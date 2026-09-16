rule o3e9_2352d5b9c2200b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.2352d5b9c2200b12"
    cluster      = "o3e9.2352d5b9c2200b12"
    cluster_size = "9"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "malicious adwaresig toolbar"
    md5_hashes   = "['40caae0e3c07dbdafbcf1625ada4a0d3','4890eab637a7425267e4e365f30a9204','c04ee7734a63ec9c8f23b53e48fe3499']"

  strings:
    $hex_string = { 11 7d 07 eb 0f f3 39 e5 ed b6 ef 58 7f 99 c5 6d de b0 ff 00 33 8a db bd 61 fe 67 15 b7 7a c3 fc ce 2b 68 7b 93 14 d6 d7 10 5c 2f ad 6f 75 0b c1 71 0f 2e 3c a2 95 19 24 5e 5f b3 c9 5b 2c 84 a5 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}