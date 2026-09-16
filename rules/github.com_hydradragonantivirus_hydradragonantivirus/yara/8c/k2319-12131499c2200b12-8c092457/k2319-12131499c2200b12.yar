rule k2319_12131499c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.12131499c2200b12"
    cluster         = "k2319.12131499c2200b12"
    cluster_size    = "19"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['62dc284d0a09ad2cc0d7f1d866f8ebee7d782841','af031766bd9af5e9bcc48900ea9901b5f1d9a8ea','ea0434ae9167191c6b09c90439295e4f3b164766']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.12131499c2200b12"

  strings:
    $hex_string = "?(2.62E2,119):(83.10E1,81.)))break};var h1D7={'x2F':function(I,K"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}