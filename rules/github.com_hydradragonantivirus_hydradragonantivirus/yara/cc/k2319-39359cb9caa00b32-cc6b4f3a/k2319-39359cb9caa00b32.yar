rule k2319_39359cb9caa00b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.39359cb9caa00b32"
    cluster         = "k2319.39359cb9caa00b32"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script adinject"
    md5_hashes      = "['9ee03a878835be9bd396d2a95445d4303dcebc71','f3ff450d8e59d4dd3bf0c3b49e004a0f1e8ff73a','4415d04d80fc092b47c9e9d4ae6f48df2d11a844']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.39359cb9caa00b32"

  strings:
    $hex_string = "var N5l in g6A7l){if(N5l.length===((14.98E2,4.66E2)<45.?'M':0x23"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}