rule k2319_393516b9c8800b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.393516b9c8800b32"
    cluster         = "k2319.393516b9c8800b32"
    cluster_size    = "35"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik diplugem script"
    md5_hashes      = "['c7b74e9006d772479266641b21b0fc27657fb6f5','3b8db7dfe82a5cffed40856dcaf670dfdbd48858','d0f87c26848115fde3f2b958aa664147d3c96538']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.393516b9c8800b32"

  strings:
    $hex_string = ",9.86E2)?(60,119):(0xF6,56)))break};var M8A3={'x2i':function(N,W"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}