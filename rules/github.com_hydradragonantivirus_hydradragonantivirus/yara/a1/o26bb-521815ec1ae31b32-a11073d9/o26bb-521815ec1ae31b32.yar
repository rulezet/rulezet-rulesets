rule o26bb_521815ec1ae31b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.521815ec1ae31b32"
    cluster         = "o26bb.521815ec1ae31b32"
    cluster_size    = "10"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "linkury zusy malicious"
    md5_hashes      = "['91449253ae874f9114d6fd6e006661a91e54af73','5580f46396872de55d3f6c60d3457648003c8e6d','855dde71a716537823db74d35a0914c0041f54c5']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.521815ec1ae31b32"

  strings:
    $hex_string = { cf 89 45 cc e8 fe e9 ff ff 83 c4 04 8b 55 f8 85 d2 74 32 8a 5f 13 80 fb 08 73 2a 0f b6 77 19 8d 87 98 00 00 00 33 c9 85 f6 7e 0d 39 50 0c 74 1c 41 83 c0 14 3b ce 7c f3 0f b6 c3 89 94 87 60 01 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}