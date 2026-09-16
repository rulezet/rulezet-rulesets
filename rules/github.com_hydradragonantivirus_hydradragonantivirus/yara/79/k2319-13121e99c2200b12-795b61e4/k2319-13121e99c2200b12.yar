rule k2319_13121e99c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.13121e99c2200b12"
    cluster         = "k2319.13121e99c2200b12"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['9bd9cde7f87836f15585f0749e9936b22e71b0db','e448d167ef11e9ffe40d6e2a5664aece99d98f67','35279bd32eee6403cd4c90943b780bf449498a7a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.13121e99c2200b12"

  strings:
    $hex_string = ",0x20D)?(75.,119):(73.3E1,91.)))break};var l9Z7j={'W5j':function"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}