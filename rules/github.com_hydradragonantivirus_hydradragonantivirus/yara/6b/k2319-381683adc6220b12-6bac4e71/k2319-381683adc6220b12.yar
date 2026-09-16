rule k2319_381683adc6220b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.381683adc6220b12"
    cluster         = "k2319.381683adc6220b12"
    cluster_size    = "28"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['aeaf3e8d9320364052ff820f06104dd028451695','6c1af9a77560ec35ddc38004c2899d0c99f19ef8','1dbe859737053308124d154229bddcc31094da7b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.381683adc6220b12"

  strings:
    $hex_string = "fined){return u[R];}var S=((0x8,11.)<=(13.88E2,75.)?(6.,0xcc9e2d"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}