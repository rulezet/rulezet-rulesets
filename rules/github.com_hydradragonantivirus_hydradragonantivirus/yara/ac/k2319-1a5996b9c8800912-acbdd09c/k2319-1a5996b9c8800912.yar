rule k2319_1a5996b9c8800912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1a5996b9c8800912"
    cluster         = "k2319.1a5996b9c8800912"
    cluster_size    = "31"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['dd7b4ee41a97b96ce0ffecc5f4285b281141dc65','fb050f16509de9185a6c2027676eda280d16eaf7','cd1f7b378c09114105cd6b171139c81cedb256b7']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1a5996b9c8800912"

  strings:
    $hex_string = "80':\"ex\",'u9M':(function(){var T=function(Z,E){var A=E&((142,10."

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}