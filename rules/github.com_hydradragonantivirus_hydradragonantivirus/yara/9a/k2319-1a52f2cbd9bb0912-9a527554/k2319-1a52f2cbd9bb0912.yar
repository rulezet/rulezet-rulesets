rule k2319_1a52f2cbd9bb0912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1a52f2cbd9bb0912"
    cluster         = "k2319.1a52f2cbd9bb0912"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script browser"
    md5_hashes      = "['b84eb5325be9889d414c7e79100a28a142116227','115a9d3052e0f058e2050959f0b42103e3612fe8','8e716a4f6df3b7a4f54ab1e6b2580c3bcdd7876b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1a52f2cbd9bb0912"

  strings:
    $hex_string = "O){return q<O;},'T9w':function(){app[(\"am\"+(53.2E1>=(8.370E2,9)?"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}