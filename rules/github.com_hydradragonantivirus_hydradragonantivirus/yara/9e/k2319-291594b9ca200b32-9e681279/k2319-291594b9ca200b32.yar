rule k2319_291594b9ca200b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.291594b9ca200b32"
    cluster         = "k2319.291594b9ca200b32"
    cluster_size    = "28"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['02694785d9c4ce85b4ac21f8a3ec5e843906abbd','32374b00ba355a5967b12c39c11db6b7497bb2c0','75d78bb15fb0b1e96c603ff969be34d5a3cd84e5']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.291594b9ca200b32"

  strings:
    $hex_string = "19):(3.,27.)))break};var R4v95={'A75':function(X,L){return X!=L;"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}