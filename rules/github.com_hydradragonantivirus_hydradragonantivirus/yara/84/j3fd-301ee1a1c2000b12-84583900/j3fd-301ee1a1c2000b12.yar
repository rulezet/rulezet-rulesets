rule j3fd_301ee1a1c2000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3fd.301ee1a1c2000b12"
    cluster      = "j3fd.301ee1a1c2000b12"
    cluster_size = "28"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "toolbar webtoolbar downtango"
    md5_hashes   = "['025e3079e61e58d527a729dda34f9c75','0cd874e5d7b8720dfbab631cfcf0984c','8a5f1ddb4533f69f145f737fb64b567d']"

  strings:
    $hex_string = { 5c 5f da 3e f3 0f 0a 09 35 22 db db c0 3f 00 f9 e6 0d 5d 67 d1 fd a0 1e 03 2b d9 40 f7 be cc 87 66 54 80 a6 a3 b8 f5 19 62 d5 d2 26 b1 98 26 ee 9a cb 44 a7 45 5a 81 95 15 1a f5 51 30 82 04 93 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}