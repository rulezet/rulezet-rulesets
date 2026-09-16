rule n3f8_492c1346ce210912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.492c1346ce210912"
    cluster         = "n3f8.492c1346ce210912"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "droidkungfu androidos kungfu"
    md5_hashes      = "['da6eb0d57cf67af7019d8fd2157ff280618a5c45','069f9a5c25e7a9e3eb2352c6a7182ef5afdc7017','9f946a142c742269753f4cf8cf429ce96b80f764']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.492c1346ce210912"

  strings:
    $hex_string = { 70 6c 61 79 41 64 4e 6f 74 69 66 69 65 72 3b 00 18 4c 63 6f 6d 2f 77 61 70 73 2f 4f 66 66 65 72 73 57 65 62 56 69 65 77 3b 00 13 4c 63 6f 6d 2f 77 61 70 73 2f 53 44 4b 55 74 69 6c 73 3b 00 1f }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}