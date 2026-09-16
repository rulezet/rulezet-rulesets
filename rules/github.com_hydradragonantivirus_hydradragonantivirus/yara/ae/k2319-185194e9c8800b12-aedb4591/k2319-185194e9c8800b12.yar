rule k2319_185194e9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.185194e9c8800b12"
    cluster         = "k2319.185194e9c8800b12"
    cluster_size    = "6"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik diplugem czyf"
    md5_hashes      = "['746b3de48935ac166412b22111f322bbc42157c8','4c570f87bb2f1286df9361b5436e39cc4c4102a6','aa98e2d73f8678192c91816c8c7006b8217805eb']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.185194e9c8800b12"

  strings:
    $hex_string = "A[K]!==undefined){return A[K];}var L=(0x4<(123,60)?(5.95E2,0xcc9"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}