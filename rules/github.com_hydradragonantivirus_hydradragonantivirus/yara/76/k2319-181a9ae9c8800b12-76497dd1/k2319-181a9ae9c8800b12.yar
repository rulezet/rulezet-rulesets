rule k2319_181a9ae9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.181a9ae9c8800b12"
    cluster         = "k2319.181a9ae9c8800b12"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['9c40db358e10362d89ecdae51d122d31203c1d37','ab76c7f6522e72143d6fa9f61bd1bdf2e593cc5f','2120d62b563d66f1625bf181dc2f02c35df783ed']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.181a9ae9c8800b12"

  strings:
    $hex_string = "break};for(var P59 in j1t59){if(P59.length===((7.95E2,0x1AD)>(0x"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}