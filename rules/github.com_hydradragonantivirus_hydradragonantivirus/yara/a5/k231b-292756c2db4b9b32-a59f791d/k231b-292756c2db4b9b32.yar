rule k231b_292756c2db4b9b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k231b.292756c2db4b9b32"
    cluster         = "k231b.292756c2db4b9b32"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "fakejquery redirector script"
    md5_hashes      = "['84407350939e6c5b610455276c0b2a1a24ff7f43','8d07d59550960fd58556f1a70967edffab0b8f7a','39669757629a693b8fc16b9b41e68e5f3b1fb276']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k231b.292756c2db4b9b32"

  strings:
    $hex_string = "yEREF9_NzfSnKjS1ORi2c0Ci1Vax8DVE9_cfqihU\" />\r\n<meta name=\"author"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}