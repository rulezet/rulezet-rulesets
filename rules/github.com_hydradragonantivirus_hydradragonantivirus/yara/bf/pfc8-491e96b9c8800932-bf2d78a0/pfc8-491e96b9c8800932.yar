rule pfc8_491e96b9c8800932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=pfc8.491e96b9c8800932"
    cluster         = "pfc8.491e96b9c8800932"
    cluster_size    = "749"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smsreg riskware androidos"
    md5_hashes      = "['823ca2c8e8066f079491fa51deee9c5a7e88d3d3','1bbf3a59fd25d0a491cae81b952ac53282511530','d009ff8aaf1ab5e5613d2f5826d980c676861839']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=pfc8.491e96b9c8800932"

  strings:
    $hex_string = { 4c 89 a9 4a b0 20 e7 9a 02 a4 90 57 63 29 5b 32 8b be 52 7a f5 9f 1d 2a 23 09 4f a7 95 e0 bf b5 b3 c0 07 22 3d 59 74 7b bc 4b 49 c8 71 13 b2 b6 f1 12 e2 8c c6 f7 11 e4 dd ce 2e da 80 c2 5e 34 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}