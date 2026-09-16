rule k2319_1c07b1add2dad111 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1c07b1add2dad111"
    cluster         = "k2319.1c07b1add2dad111"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script asmalwsc"
    md5_hashes      = "['0f09bc9a11abd240db9f68833ce172796aa6f4b7','06fe58582632854b91a2cc814862967eb7d780df','29999d286d039c0912423e797ecf45631fd0448b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1c07b1add2dad111"

  strings:
    $hex_string = "ndefined){return O[u];}var r=(0x21<=(1.219E3,0x1CA)?(7.96E2,0xcc"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}