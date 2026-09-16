rule k2319_1100b1cbc2220b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1100b1cbc2220b32"
    cluster         = "k2319.1100b1cbc2220b32"
    cluster_size    = "13"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "multiplug kryptik diplugem"
    md5_hashes      = "['28105a1b7d208d85594642e2737228784f95e332','fdfe8593ccf67ac11ddcec0f0a5c8a910fc5bd1f','10974bb19838bf44b21925fe795dedc544939448']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1100b1cbc2220b32"

  strings:
    $hex_string = "F)<=3.6E1?\"G\":(106.,48.)))break};var l6U0={'z7R':1,'s6m':functio"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}