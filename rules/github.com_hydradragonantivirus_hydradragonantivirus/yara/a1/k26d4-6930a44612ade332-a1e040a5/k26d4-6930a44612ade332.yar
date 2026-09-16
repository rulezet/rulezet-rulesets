rule k26d4_6930a44612ade332 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26d4.6930a44612ade332"
    cluster         = "k26d4.6930a44612ade332"
    cluster_size    = "12"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "hacktool patcher riskware"
    md5_hashes      = "['e4332c40c3db79074ed7dee3b2c74c5f615314c6','85b84ee2988aea5da8af963656edc12d3f823f1d','ca0cf428af0285dbd10524fc50517eb818f55efd']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26d4.6930a44612ade332"

  strings:
    $hex_string = { 5d 08 8b 7d 0c 8b d3 0f b7 43 3c 03 d8 8b 5b 78 03 da 0b ff 74 40 8b 4b 18 8b 73 20 03 f2 53 33 db ad 03 c2 56 57 87 f7 97 ac 0a c0 75 07 80 3f 00 74 0b eb 07 38 07 75 03 47 eb ed b0 01 5f 5e }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}