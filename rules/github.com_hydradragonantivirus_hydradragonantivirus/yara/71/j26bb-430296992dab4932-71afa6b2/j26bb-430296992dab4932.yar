rule j26bb_430296992dab4932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j26bb.430296992dab4932"
    cluster         = "j26bb.430296992dab4932"
    cluster_size    = "28"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "webprefix xjltf malicious"
    md5_hashes      = "['60668a24adc68d1426d5067de2e6d55ba92026b0','8d00652a20502c43917dd0bfde1f8f89cebe54eb','fcb1ab1a147edf72d93015e5c70f5433968aedd0']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j26bb.430296992dab4932"

  strings:
    $hex_string = { 7d a5 d9 06 0d bc 20 98 14 05 73 b3 34 4b 94 25 90 2d 8c 9c 8f 7f b6 b1 c2 c0 97 56 b4 07 04 b8 8d 45 08 78 a6 5b 3c c4 08 e0 fc 21 23 bf 87 b7 39 43 01 a1 1c 15 b4 13 20 a8 c1 69 6c 81 09 71 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}