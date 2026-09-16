rule k2319_2904a695dbabdb12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.2904a695dbabdb12"
    cluster         = "k2319.2904a695dbabdb12"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script plugin"
    md5_hashes      = "['e43838dbca72fa1f5c1f6ba42477614f5569cd32','8c767ab71f3817c3b2137cbc88e549983b79ea0f','4547cc61829686ed839d041c09b21e53334eed6e']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.2904a695dbabdb12"

  strings:
    $hex_string = "12.19E2):(48,0x239)))break};var S8Z={'P1g':'s','R4':function(w,t"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}