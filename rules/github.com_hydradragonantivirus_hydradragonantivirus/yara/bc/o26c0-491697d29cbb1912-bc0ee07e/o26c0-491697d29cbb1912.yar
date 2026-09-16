rule o26c0_491697d29cbb1912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.491697d29cbb1912"
    cluster         = "o26c0.491697d29cbb1912"
    cluster_size    = "23"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "strictor malicious filerepmalware"
    md5_hashes      = "['6d7d6c2c08c409b3121d54cc28c683f9601f26c6','879b114fd8a961c7ace007e1771d4f48183fc99f','9b95d8dd2399cc0e8dec1740e5d74f3ad39de8c6']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.491697d29cbb1912"

  strings:
    $hex_string = { c9 69 e6 ff 15 99 47 e3 39 6a 4f a3 b9 2f 8b d5 f1 2b 48 19 1c 24 1a 6d 54 88 2d 86 b2 0e 11 4c 87 f2 0d da 64 3c 51 50 9e ea ec 9f 8a 08 8f f3 e9 cd 56 34 00 3b db 53 b6 2a 4d 01 33 3d 83 65 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}