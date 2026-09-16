rule k26bb_193e69e159b2e316 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.193e69e159b2e316"
    cluster         = "k26bb.193e69e159b2e316"
    cluster_size    = "18"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "installcore unwanted dealply"
    md5_hashes      = "['4f3ac0785a35924b4860b93e10aeba4dd5241b4a','f3e6e0a27752cb732af116f1cc5288becb76bfa9','f94a589f5f21a4994be53eba6a29e7d66f2caaf2']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.193e69e159b2e316"

  strings:
    $hex_string = { 16 54 43 6f 6d 70 72 65 73 73 65 64 42 6c 6f 63 6b 52 65 61 64 65 72 90 56 33 f6 b9 5c c5 40 00 8b c6 ba 08 00 00 00 a8 01 74 09 d1 e8 35 20 83 b8 ed eb 02 d1 e8 4a 75 ee 89 01 46 83 c1 04 81 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}