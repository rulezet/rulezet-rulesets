rule o26d4_51e1e482c0000132 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26d4.51e1e482c0000132"
    cluster         = "o26d4.51e1e482c0000132"
    cluster_size    = "13374"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy bitminer malicious"
    md5_hashes      = "['b0aa65e145b0e9d728d5a310ccc5355e68771dac','c62f39e04d90b175dc3de422b6b5440316c094d9','e2a2fe90e2bab6c283709e689088cbf4a427bdbc']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26d4.51e1e482c0000132"

  strings:
    $hex_string = { 75 04 2a 98 2b bd f8 d5 f2 d2 39 62 e7 20 c6 b4 f4 da 26 1b a1 41 5c 46 c3 c4 5f e0 61 b1 1e 29 3e 91 cd 9b b6 c5 36 6a 84 e3 10 1a 6e ba 0d 34 8d f7 c0 12 15 e4 bc 40 27 5e cb d9 ea a4 dd 80 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}