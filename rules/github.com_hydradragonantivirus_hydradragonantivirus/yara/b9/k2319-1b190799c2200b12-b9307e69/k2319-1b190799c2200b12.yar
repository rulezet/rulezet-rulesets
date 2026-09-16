rule k2319_1b190799c2200b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2319.1b190799c2200b12"
    cluster         = "k2319.1b190799c2200b12"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kryptik script diplugem"
    md5_hashes      = "['dada4f1aa121f238cb253d49f580929f6120118c','7954ef2e55b1189a48b5e7f47832eb3002d19c07','b4e8e3d4df6fa8e189db2e70c024ad9f45393c6b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2319.1b190799c2200b12"

  strings:
    $hex_string = "fined){return K[G];}var L=(68.10E1>(1.183E3,133)?(0x13A,0xcc9e2d"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}