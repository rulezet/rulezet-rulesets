rule k2319_120a92b9c2200912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.120a92b9c2200912"
    cluster         = "k2319.120a92b9c2200912"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['e6f3e00715d929a96dd6ac87f809c747be883a32','bbca58cc82a2ff4edd3ec417a276f62ab58277b7','4dd85d7b0decb1376380b3b0ae1f9f62a8b4c85b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.120a92b9c2200912"

  strings:
    $hex_string = "?(1.036E3,119):(96.5E1,0x1A)))break};var y5Y7l={'Q9l':function(j"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}