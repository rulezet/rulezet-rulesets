rule k2319_1a1194b9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1a1194b9c8800b12"
    cluster         = "k2319.1a1194b9c8800b12"
    cluster_size    = "9"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik diplugem script"
    md5_hashes      = "['a64552b3ab276474dba0c6bebffabc95f023839a','5620b56528c18c667d5431390e3bdcb0c119fedd','368ad27f449a6db41c9581ac2b3ae23056140d60']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1a1194b9c8800b12"

  strings:
    $hex_string = "x1A0,119):(9.58E2,12.700E2)))break};var Z7z6H={'M6H':function(w,"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}