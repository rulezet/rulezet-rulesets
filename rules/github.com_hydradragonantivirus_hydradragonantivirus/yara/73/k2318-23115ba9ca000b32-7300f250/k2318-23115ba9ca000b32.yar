rule k2318_23115ba9ca000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2318.23115ba9ca000b32"
    cluster         = "k2318.23115ba9ca000b32"
    cluster_size    = "2363"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "iframe html redir"
    md5_hashes      = "['c6af3aa551c269f59471b0eb761d94f5f9d13b7e','0fb4bb81f83f392e5c6482f607034d877d3edc05','4efc442cfc7faf72da19aa392660a7c4338180bd']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2318.23115ba9ca000b32"

  strings:
    $hex_string = { 7a 65 3d 22 31 22 20 73 74 79 6c 65 3d 22 77 69 64 74 68 3a 20 31 30 30 25 22 3e 3c 6f 70 74 69 6f 6e 20 76 61 6c 75 65 3d 22 22 20 53 45 4c 45 43 54 45 44 3e c2 fb e1 e5 f0 e8 f2 e5 3c 2f 6f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}