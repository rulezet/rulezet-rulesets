rule k2319_1a129ae9c8800912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1a129ae9c8800912"
    cluster         = "k2319.1a129ae9c8800912"
    cluster_size    = "14"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik decode multiplug"
    md5_hashes      = "['2c7ed7fdb0c76859139255b13fd3e6544831205e','7a228617ea545cf609fb372e0a050cd4ff72f1dd','3ea026278674da36b32f7b30ac9d425aaf73823b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1a129ae9c8800912"

  strings:
    $hex_string = "(w[t]!==undefined){return w[t];}var P=((0x194,0xFA)<142?(108.30E"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}