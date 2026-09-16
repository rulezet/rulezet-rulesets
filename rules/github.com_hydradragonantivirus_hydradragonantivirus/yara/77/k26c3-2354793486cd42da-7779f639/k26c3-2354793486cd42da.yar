rule k26c3_2354793486cd42da {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26c3.2354793486cd42da"
    cluster         = "k26c3.2354793486cd42da"
    cluster_size    = "66"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "mirai linux backdoor"
    md5_hashes      = "['f51ec247df998ad7458dec645e11f298d853eebe','51e71804e962c539f880c03b43bd0b65c755141e','a389b68662aabdf160b0f4d21d4d23c6ba5df26a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26c3.2354793486cd42da"

  strings:
    $hex_string = { b8 c4 27 bf b4 c2 07 bf e8 05 3c 3f ff 86 09 20 01 9a 0c a0 01 88 0d 60 01 98 0c 60 01 aa 00 60 28 d6 07 bf c4 87 28 e0 13 97 2a e0 18 89 29 20 12 9b 2b 60 11 99 2b 20 10 03 03 ff ff b4 10 a3 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}