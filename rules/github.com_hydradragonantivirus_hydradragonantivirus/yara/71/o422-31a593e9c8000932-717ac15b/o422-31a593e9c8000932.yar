rule o422_31a593e9c8000932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o422.31a593e9c8000932"
    cluster         = "o422.31a593e9c8000932"
    cluster_size    = "28"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "jacard delf malicious"
    md5_hashes      = "['2e3250d25eb3afe9fb738cde307cda763732d706','767e799b10d25a3de1342c36e32ad70a408887ca','da6669da8d82f9b97bf786b9638f17a1fb5327a8']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o422.31a593e9c8000932"

  strings:
    $hex_string = { 45 7c 3e 54 b5 a2 61 66 5c 0d cc e5 d1 57 69 1b 78 28 50 e7 42 48 7a 60 6d c5 f4 b2 1d ac b7 7f 9b c3 ad ae 04 0b 14 a8 19 73 58 97 08 23 05 8e 4d 12 af f7 47 3a 55 cb 3b ab 9c bb b6 ee 4b 9f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}