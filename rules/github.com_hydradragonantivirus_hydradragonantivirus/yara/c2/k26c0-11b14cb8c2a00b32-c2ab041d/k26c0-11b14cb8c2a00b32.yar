rule k26c0_11b14cb8c2a00b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26c0.11b14cb8c2a00b32"
    cluster         = "k26c0.11b14cb8c2a00b32"
    cluster_size    = "25"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "clipspy malicious attribute"
    md5_hashes      = "['d67781f644471404e662c99f512d13047db165b1','9ad74fe378bbe73cdec2bc911241b212c750432f','15f7deaa0c95c2a869de85cc1bd7f3adf50d8b08']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26c0.11b14cb8c2a00b32"

  strings:
    $hex_string = { 7a 65 5f 63 6f 73 74 00 07 14 01 a5 09 00 00 15 69 78 38 36 5f 74 75 6e 65 5f 69 6e 64 69 63 65 73 00 04 f8 00 00 00 07 6b 01 5a 14 00 00 11 58 38 36 5f 54 55 4e 45 5f 53 43 48 45 44 55 4c 45 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}