rule j26d4_14a22ba1cac3f16a {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j26d4.14a22ba1cac3f16a"
    cluster         = "j26d4.14a22ba1cac3f16a"
    cluster_size    = "22"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "malicious proxy atraps"
    md5_hashes      = "['5bba86b7ec0b284578b064ac47bb91abd7a08432','c210deff8f142239026bc789a014337e9366c051','6b10743bc8145d253187126e2aa3ce8a0af0d538']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j26d4.14a22ba1cac3f16a"

  strings:
    $hex_string = { 4b 50 46 46 ff 37 4e 4e 81 eb 88 23 01 00 5b 58 83 fb 00 0f 85 f7 09 00 00 0f 84 1e 0a 00 00 d3 fa 58 9b 1d 94 20 b9 81 b4 2c be 81 f2 2e 93 81 b2 3c bf cb d2 0a d7 47 f3 56 c6 6d ab 6b 22 12 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}