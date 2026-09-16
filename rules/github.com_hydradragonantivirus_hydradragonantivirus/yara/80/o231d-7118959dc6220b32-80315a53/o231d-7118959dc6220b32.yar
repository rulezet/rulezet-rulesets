rule o231d_7118959dc6220b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o231d.7118959dc6220b32"
    cluster         = "o231d.7118959dc6220b32"
    cluster_size    = "32"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "fakeapp androidos riskware"
    md5_hashes      = "['4e1652ad317aa0554df510c1350804dae1f13cf2','6277e50e316b70f121324566df43645686d678df','0a1a14c0fd8c27ad3f9457400f68d9432886321b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o231d.7118959dc6220b32"

  strings:
    $hex_string = { 0a f8 e2 c5 bd 5a 2d fd 81 fb 4a fc 2f 9e 18 fe 98 d6 11 92 4b af b9 7a 9c 72 68 0e a6 c6 58 45 ef 7b a9 07 04 2b cf ba da 5e e8 63 c7 03 ed 02 35 79 c0 7c 39 46 f3 43 0d f4 db b7 74 4d 87 ee }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}