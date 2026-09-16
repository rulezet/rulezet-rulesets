rule j26bf_111e66c8c0000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=j26bf.111e66c8c0000b32"
    cluster         = "j26bf.111e66c8c0000b32"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "barys malicious tomc"
    md5_hashes      = "['365081a937524b7a7ef990f080f183ea2a0640a9','9967ff63de6192ac577ff12ec374f03228b1dc13','58a322344ce2275f81b92ec83522f801ccb22585']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=j26bf.111e66c8c0000b32"

  strings:
    $hex_string = { 00 54 68 72 65 61 64 53 61 66 65 4f 62 6a 65 63 74 50 72 6f 76 69 64 65 72 60 31 00 41 00 4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 42 61 73 69 63 2e 41 70 70 6c 69 63 61 74 69 6f 6e 53 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}