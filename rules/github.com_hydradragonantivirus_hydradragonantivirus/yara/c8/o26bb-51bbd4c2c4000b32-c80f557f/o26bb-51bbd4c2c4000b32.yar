rule o26bb_51bbd4c2c4000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.51bbd4c2c4000b32"
    cluster         = "o26bb.51bbd4c2c4000b32"
    cluster_size    = "471"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "linkury ursu heuristic"
    md5_hashes      = "['9039dd03a214620383ae818cd885a37031c809ad','fdd839f749e12c6fc1bbdaabeab04790d376ac40','c9fbcce9b10ec2537a8a7bf3e159a45a52052472']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.51bbd4c2c4000b32"

  strings:
    $hex_string = { f0 83 c4 18 85 f6 75 20 be ff ff ff 7f eb 19 8b 55 0c 33 c9 85 f6 74 10 8b 7d 08 0f b6 04 11 66 89 04 4f 41 3b ce 72 f3 52 e8 2a 42 00 00 59 5f 8b c6 5e 5b 5d c3 55 8b ec 51 8d 45 fc 50 6a 01 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}