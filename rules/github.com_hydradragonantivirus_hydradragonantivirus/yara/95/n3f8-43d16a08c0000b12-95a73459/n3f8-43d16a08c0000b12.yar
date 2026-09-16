rule n3f8_43d16a08c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.43d16a08c0000b12"
    cluster         = "n3f8.43d16a08c0000b12"
    cluster_size    = "210"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "zdtad androidos inoco"
    md5_hashes      = "['aa178ce6bb6db6e895a2e990e4dceac602111498','a44a190519c045980c9c240e0b63038781d57a36','5e3b78b28b30e1887b769c6d0f6dec890fffd1bb']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.43d16a08c0000b12"

  strings:
    $hex_string = { 73 68 69 6e 67 e7 8a b6 e6 80 81 29 00 1e 73 74 61 72 74 41 64 31 28 e5 88 9d e5 a7 8b e5 8c 96 e9 94 99 e8 af af 20 e4 bc a0 e5 85 a5 e7 9a 84 63 6f 6e 74 65 78 e4 b8 ba 6e 75 6c 6c 29 00 25 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}