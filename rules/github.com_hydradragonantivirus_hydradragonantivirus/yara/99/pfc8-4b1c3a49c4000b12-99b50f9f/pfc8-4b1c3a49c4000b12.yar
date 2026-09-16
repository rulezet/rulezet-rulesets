rule pfc8_4b1c3a49c4000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=pfc8.4b1c3a49c4000b12"
    cluster         = "pfc8.4b1c3a49c4000b12"
    cluster_size    = "822"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smsreg riskware androidos"
    md5_hashes      = "['87569e3bc2ffedff492e76523036202bc2a0098c','89bad8ddaaae278f339a7468fe2a2d4a2f3f9342','73d1e81cbf89c213e58ab0eb85604ebac4574db1']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=pfc8.4b1c3a49c4000b12"

  strings:
    $hex_string = { 7c c4 f8 13 11 a7 c2 9f 9c 2c e6 0f 47 54 78 e9 1e 20 e2 6b b9 43 a4 f7 38 e5 40 87 6a 76 27 ef d4 ab 8c 4b 0b 18 f3 89 b7 94 f6 30 28 49 95 e3 82 88 e7 cb bd 6e 1f ee 52 60 f0 50 da 58 d9 65 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}