rule o26bb_45e2d7a3ca000932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.45e2d7a3ca000932"
    cluster         = "o26bb.45e2d7a3ca000932"
    cluster_size    = "16"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "strictor malicious autoit"
    md5_hashes      = "['b05361c85892dd13f9410df73f05e9eac4b4f3d9','0bbad4e872aa35b07325eeddb0281914be3fcc8a','fbc5ff5cf02da8941fcb1c8205660e7a9cdae16e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.45e2d7a3ca000932"

  strings:
    $hex_string = { d1 f8 88 0c 10 3b f7 7c c0 b0 01 5e 5f 5b 8b e5 5d c3 32 c0 eb f5 55 8b ec 51 53 56 57 8b f9 8b f2 57 e8 94 d3 fb ff 83 26 00 59 33 c9 c7 45 fc 30 00 00 00 41 8d 50 ff 33 db 85 d2 78 3f 0f b7 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}