rule k26bb_6394b3f9c2200b16 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.6394b3f9c2200b16"
    cluster         = "k26bb.6394b3f9c2200b16"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious virut attribute"
    md5_hashes      = "['caa88d929c1ff90215f8d3137df15c46f5238767','092236af6de2a212b349af38c5fa060b2917b3ba','023b0a61a19d3bb682e90095e83d3e744bccc4c4']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.6394b3f9c2200b16"

  strings:
    $hex_string = { 75 08 ff d6 85 c0 75 11 40 39 45 f4 74 0d ff 37 ff 15 fc 10 00 01 83 27 00 33 c0 5f 5e c9 c2 0c 00 cc cc cc cc cc 8b ff 55 8b ec 83 ec 1c 53 8b 5d 0c 8b 43 08 56 33 f6 3b c6 74 0f 50 68 5c 04 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}