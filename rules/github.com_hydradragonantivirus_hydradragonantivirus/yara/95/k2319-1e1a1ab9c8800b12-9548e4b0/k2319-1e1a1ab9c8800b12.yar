rule k2319_1e1a1ab9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1e1a1ab9c8800b12"
    cluster         = "k2319.1e1a1ab9c8800b12"
    cluster_size    = "20"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['323a228e488569d9917df1ee25a85543446c557e','31dd3e06f1c9f4153d1da5b49ff1efb0da46548d','3133266b6acbc09198836a727ee0fd7c816818f7']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1e1a1ab9c8800b12"

  strings:
    $hex_string = "0E1,119):(84.,143)))break};var a7D5={'l5f':\"in\",'w4':function(q,"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}