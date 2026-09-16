rule o2321_49910ac4fa630912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o2321.49910ac4fa630912"
    cluster      = "o2321.49910ac4fa630912"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut graftor shodi"
    md5_hashes   = "['11f209cf000fea16134ba0f5dd9f393d','1b946245b2347bfe2858e43e05141a8c','d8939968372587bc7d40ee0ec9164097']"

  strings:
    $hex_string = { 4a 2b 4e 4c 76 ee 84 2f 81 7c 20 50 bf 28 30 29 62 b1 3c ab 54 2e a7 3e fb a0 cf a1 53 1e a9 04 52 f9 85 1a 8c 36 a4 7d 37 17 cb 99 7e b9 95 92 96 27 be b7 e4 14 4d dd 5e 58 a3 90 6c 9e 73 97 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}