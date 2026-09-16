rule k2319_291f3949c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.291f3949c0000b12"
    cluster         = "k2319.291f3949c0000b12"
    cluster_size    = "63"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "diplugem script asmalwsc"
    md5_hashes      = "['ec08f768bfa07ba68673d1da53726e56c05a1668','ec6d858f6a199f33cafb13a7d0e2b19a6185a879','9977aa6dabf5b9c0d7328f0684e45502dbd8911a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.291f3949c0000b12"

  strings:
    $hex_string = ",v){if(!F||!F[t5X5.g36]){return ;};switch(F[t5X5.g36]){default:v"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}