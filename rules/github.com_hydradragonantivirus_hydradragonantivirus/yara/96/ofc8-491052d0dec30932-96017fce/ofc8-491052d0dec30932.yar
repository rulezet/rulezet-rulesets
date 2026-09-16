rule ofc8_491052d0dec30932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.491052d0dec30932"
    cluster         = "ofc8.491052d0dec30932"
    cluster_size    = "4"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smspay riskware shedun"
    md5_hashes      = "['133309ef8bbd12e6d83f7b8abec03b32219253d0','c371926ca6b1a527bdbf0b4280ebb76827fb8a73','93e3975199ac54b3b4a1f68fe9138fd0a993cd12']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.491052d0dec30932"

  strings:
    $hex_string = { 30 ce d0 f7 a3 5c fa 93 e3 55 9a 7c 13 c8 ef 10 07 de ec cd 7b 96 58 92 fb 69 00 0c a5 53 e1 24 c1 86 78 c6 3d e5 df 04 2f cb 9d 7a 50 dc 9b 1c 01 7f 02 67 2e 65 6e 27 0d c0 db 8e 42 3a 0e 18 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}