rule j2321_24a9e2259ebb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.24a9e2259ebb1912"
    cluster      = "j2321.24a9e2259ebb1912"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "selfdel generickd upatre"
    md5_hashes   = "['60043eb9e4d1b9b561ee2afcb0f80613','71d66c87e25f8cf4d4cc9d6b83614ff2','d8ea4484e5cb1ad63941b91a27c80962']"

  strings:
    $hex_string = { 7e 0d bf 1e 12 82 74 97 3b a6 51 14 df 63 6e 8d 42 3f 0e ce 4f 9a 85 f5 a0 63 a5 2f a0 3d 7b 0b 8e d5 20 7f bb 6e 53 72 50 cf f3 fa 40 27 94 5f f8 2b 6c 46 f9 91 03 fb 6f 47 b9 ef 35 d1 d4 61 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}