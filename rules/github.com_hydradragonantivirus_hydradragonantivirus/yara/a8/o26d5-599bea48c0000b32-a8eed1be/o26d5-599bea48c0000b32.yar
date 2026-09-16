rule o26d5_599bea48c0000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26d5.599bea48c0000b32"
    cluster         = "o26d5.599bea48c0000b32"
    cluster_size    = "118"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "razy malicious gifq"
    md5_hashes      = "['d7b59be814cc65c0f58cdd6fde68fff44c075560','e59a8cc3092b24c84d425cacdf90f9f636f83e3b','12180f007490c6777e30741f9ca0d4705fed7820']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26d5.599bea48c0000b32"

  strings:
    $hex_string = { 47 65 74 43 6f 6e 73 6f 6c 65 43 50 00 00 00 00 53 65 74 55 6e 68 61 6e 64 6c 65 64 45 78 63 65 70 74 69 6f 6e 46 69 6c 74 65 72 00 00 00 45 6e 75 6d 52 65 73 6f 75 72 63 65 54 79 70 65 73 41 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}