rule o2319_1198e448c0000912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.1198e448c0000912"
    cluster         = "o2319.1198e448c0000912"
    cluster_size    = "12"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "coinminer miner coinhive"
    md5_hashes      = "['8023a77ee9d92338ee4e70bbaed7f4f51ae72325','a7a8249cc568323cdb8f00b1646d6e7789651019','0f712ba82b9a3acf03d53c157651ba53316aa6e7']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.1198e448c0000912"

  strings:
    $hex_string = { 67 50 72 65 66 69 78 3a 22 e8 ad a6 e5 91 8a ef bc 9a 22 2c 6e 6f 53 70 61 63 65 3a 22 e4 b8 8d e8 83 bd e5 8c 85 e5 90 ab e7 a9 ba e6 a0 bc e3 80 82 20 22 2c 72 65 71 43 68 6b 42 79 4e 6f 64 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}