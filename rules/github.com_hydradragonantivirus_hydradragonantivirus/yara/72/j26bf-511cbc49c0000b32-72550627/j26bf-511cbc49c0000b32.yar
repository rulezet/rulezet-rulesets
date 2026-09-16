rule j26bf_511cbc49c0000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j26bf.511cbc49c0000b32"
    cluster         = "j26bf.511cbc49c0000b32"
    cluster_size    = "177"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "zusy starter malicious"
    md5_hashes      = "['2e90e32ac36e3ee8272b97868c86f78fd2ee484c','746ff8e3498fa8c50827354fee38543cfb684341','36452e3a87b6c2b3f5a4e380058785dc9d52a7f9']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j26bf.511cbc49c0000b32"

  strings:
    $hex_string = { 00 46 01 80 00 06 00 c4 01 e7 00 0e 00 57 02 41 02 0e 00 70 02 41 02 0e 00 9d 02 85 02 06 00 c7 02 b4 02 0a 00 06 03 df 02 0a 00 1e 03 13 00 0e 00 53 03 36 03 06 00 88 03 68 03 06 00 a6 03 e7 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}