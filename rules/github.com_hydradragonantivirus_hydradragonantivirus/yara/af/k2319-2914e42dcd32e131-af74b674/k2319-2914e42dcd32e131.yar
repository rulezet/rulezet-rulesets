rule k2319_2914e42dcd32e131 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.2914e42dcd32e131"
    cluster         = "k2319.2914e42dcd32e131"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script plugin"
    md5_hashes      = "['408b53f4fa261569eb5b0f39c847b26af22d9203','164a02be5be059340e9754bf650a0b77d5171e2e','85297452b52e97b53bf0724ea7109347ecdf5233']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.2914e42dcd32e131"

  strings:
    $hex_string = "!==undefined){return G[d];}var U=((33.0E1,82)<(58.,78)?'v':0x2D<"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}