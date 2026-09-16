rule n3f8_5a06e44980000110 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.5a06e44980000110"
    cluster         = "n3f8.5a06e44980000110"
    cluster_size    = "53"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos banker piom"
    md5_hashes      = "['c413b80aa108a819ca1aa7000f78b05ffa11a01a','d22ed2ec71153d6ee4529072b26080811e830b94','ebb2f608c60fb95ba70b81f8e472d465738d14ff']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.5a06e44980000110"

  strings:
    $hex_string = { 31 3b 00 36 4c 63 6f 6d 2f 73 71 75 61 72 65 75 70 2f 68 61 68 61 2f 67 75 61 76 61 2f 63 6f 6c 6c 65 63 74 2f 4d 61 70 73 24 45 6e 74 72 79 46 75 6e 63 74 69 6f 6e 24 32 3b 00 34 4c 63 6f 6d }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}