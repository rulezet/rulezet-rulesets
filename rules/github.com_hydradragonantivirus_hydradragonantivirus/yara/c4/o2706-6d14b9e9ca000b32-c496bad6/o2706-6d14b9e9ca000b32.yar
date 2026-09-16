rule o2706_6d14b9e9ca000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2706.6d14b9e9ca000b32"
    cluster         = "o2706.6d14b9e9ca000b32"
    cluster_size    = "25"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "browsefox ursu malicious"
    md5_hashes      = "['e298e8ba0bd1f9ce715c37adba01a0d774a03f95','938c0390a6d699af39f68d72b0a4f7f85baa461b','14268768fac545f937a6886dc7eb3136e181d52b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2706.6d14b9e9ca000b32"

  strings:
    $hex_string = { 5f 44 65 66 61 75 6c 74 53 65 74 74 69 6e 67 73 00 66 6f 72 6d 61 74 00 74 69 6d 65 5a 6f 6e 65 48 61 6e 64 6c 69 6e 67 00 63 63 36 38 30 30 38 31 39 33 35 33 33 30 38 36 35 64 61 34 62 31 62 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}