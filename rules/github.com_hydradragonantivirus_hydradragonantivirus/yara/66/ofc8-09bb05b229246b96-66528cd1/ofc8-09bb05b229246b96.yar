rule ofc8_09bb05b229246b96 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.09bb05b229246b96"
    cluster         = "ofc8.09bb05b229246b96"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smspay riskware shedun"
    md5_hashes      = "['220c817493b2019eadbdc887dc0bb24fef6b26e1','0aeaa4f821213390c546730c72d552c4a1c4f0b1','d8f23381094ebbae0bdca6d7fd5da6bb34a0094d']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.09bb05b229246b96"

  strings:
    $hex_string = { d3 02 b9 5b 64 20 1d da cc 87 e6 c2 b0 04 8d 67 f5 74 d2 9b 5c 12 d1 47 4f 11 d6 5f 06 fd 92 eb 3c a8 75 e8 d8 db 77 8b aa b2 05 dd 1e 46 00 e4 ba 35 9c 89 07 50 9a b3 91 a3 3b df 6c 1a c4 f0 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}