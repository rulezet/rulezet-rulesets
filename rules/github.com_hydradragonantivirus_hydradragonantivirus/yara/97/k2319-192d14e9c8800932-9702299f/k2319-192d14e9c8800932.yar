rule k2319_192d14e9c8800932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.192d14e9c8800932"
    cluster         = "k2319.192d14e9c8800932"
    cluster_size    = "14"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['37fd75dde9daf8fc83c3700e96613cb09a9d55c1','35c7d45d4688357204109f1a9fdb1b5f00d8cba6','fa6077c8cfeb40f21f0b677cf82e3624cbae41d4']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.192d14e9c8800932"

  strings:
    $hex_string = "fined){return r[t];}var H=((14.870E2,26.)<=0xC8?(0x124,0xcc9e2d5"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}