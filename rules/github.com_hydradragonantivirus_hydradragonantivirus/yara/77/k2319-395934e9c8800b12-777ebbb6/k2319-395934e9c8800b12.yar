rule k2319_395934e9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.395934e9c8800b12"
    cluster         = "k2319.395934e9c8800b12"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['9c6f08fc554f2a9064026c631dc5e8e51368ed35','c27921e4b07e96a51d96b7a2b87677a5bb06d388','5421b8a960c1ce59889da0f391a618f5ea714b01']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.395934e9c8800b12"

  strings:
    $hex_string = "ndefined){return p[S];}var R=((144.5E1,0x21A)>142?(1.341E3,0xcc9"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}