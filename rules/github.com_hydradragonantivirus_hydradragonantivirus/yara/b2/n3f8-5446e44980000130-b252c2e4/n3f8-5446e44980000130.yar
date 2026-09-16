rule n3f8_5446e44980000130 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.5446e44980000130"
    cluster         = "n3f8.5446e44980000130"
    cluster_size    = "26"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "banker androidos asacub"
    md5_hashes      = "['7d9956e1491bdc37d76022c566a66250092f02ee','1115ece890565a85ea5c106abf5a04d63b04daf0','c158835f4c3a75a8585cc0289fa624ba440de7fd']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.5446e44980000130"

  strings:
    $hex_string = { 79 2f 41 6e 64 72 6f 69 64 57 61 74 63 68 45 78 65 63 75 74 6f 72 3b 00 25 4c 63 6f 6d 2f 73 71 75 61 72 65 75 70 2f 6c 65 61 6b 63 61 6e 61 72 79 2f 42 75 69 6c 64 43 6f 6e 66 69 67 3b 00 31 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}