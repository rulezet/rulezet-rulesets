rule o26d4_39b85ac348001132 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26d4.39b85ac348001132"
    cluster         = "o26d4.39b85ac348001132"
    cluster_size    = "880"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy kryptik adposhel"
    md5_hashes      = "['f648a18253d275ed497abe9e036110f2c836a8ae','689abd75c735187730af610c595ab061dcdc033b','802e916fb2a2ab1f63e5f329a7aceaf1b143d542']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26d4.39b85ac348001132"

  strings:
    $hex_string = { 00 6f d9 02 4e f0 d4 e1 e2 28 16 c2 63 f0 d4 e1 e2 e3 12 a2 5e 10 d8 13 79 f0 d4 e1 e2 dc f8 ae 94 f0 d4 e1 e2 74 87 26 52 03 41 a0 7b f0 d4 e1 e2 d8 57 0a 23 f0 d4 e1 e2 be d7 1c b8 c3 ea 6b }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}