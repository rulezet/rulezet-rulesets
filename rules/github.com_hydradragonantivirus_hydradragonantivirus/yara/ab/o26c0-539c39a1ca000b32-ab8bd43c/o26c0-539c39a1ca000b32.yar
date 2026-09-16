rule o26c0_539c39a1ca000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.539c39a1ca000b32"
    cluster         = "o26c0.539c39a1ca000b32"
    cluster_size    = "33"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "midie kryptik malicious"
    md5_hashes      = "['8bbf70332f516ea683999023440b59915cb2d8cd','8615e99c5e5994271731c2e58660cde35181008f','1a0f7c2842b492b9fa56ec2e7049b2ae551d4b88']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.539c39a1ca000b32"

  strings:
    $hex_string = { 08 03 f8 89 7e 34 8b 4e 28 85 c9 7f 06 8b c3 0b c2 74 3a 6a 00 ff 75 10 8d 41 ff 52 53 89 46 28 e8 34 51 01 00 80 c1 30 89 5d fc 8b d8 80 f9 39 7e 11 80 7d 14 00 0f 94 c0 fe c8 24 e0 04 61 2c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}