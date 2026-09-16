rule o2319_1972ea48c0000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.1972ea48c0000b32"
    cluster         = "o2319.1972ea48c0000b32"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "faceliker clickjack likejack"
    md5_hashes      = "['6210dbaa39b912d868a0e6b12060ddd755ba058e','9e8981b520ae5a64b671d5ecd27a196b3a8ec59c','370594e19afc071cbea09369ae54f077d0eb74bd']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.1972ea48c0000b32"

  strings:
    $hex_string = "=\"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}