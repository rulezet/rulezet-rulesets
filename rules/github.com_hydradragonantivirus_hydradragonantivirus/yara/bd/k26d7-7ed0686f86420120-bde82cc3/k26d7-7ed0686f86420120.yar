rule k26d7_7ed0686f86420120 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26d7.7ed0686f86420120"
    cluster         = "k26d7.7ed0686f86420120"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy malicious webprefix"
    md5_hashes      = "['69dd89a2c2ca7c66931c7e95d05569663f35e25a','ce9d58274684dc2c735c4e1c97b4f13ba7c5e460','8b7782ffbc6bbed5333a5c2cc609b65a98d74f7a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26d7.7ed0686f86420120"

  strings:
    $hex_string = { 73 bb 1d a2 a5 79 27 30 b3 06 b0 22 29 11 2e 31 43 8b 2d 92 95 49 17 00 83 36 a7 32 09 01 3e 21 53 9b 3d 82 85 59 07 10 93 26 54 c2 e9 f1 ce d1 a3 6b cd 72 75 a9 f7 e0 63 d6 4b d2 89 e1 de c1 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}