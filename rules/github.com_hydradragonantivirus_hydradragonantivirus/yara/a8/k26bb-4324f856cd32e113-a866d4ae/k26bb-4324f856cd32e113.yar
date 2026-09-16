rule k26bb_4324f856cd32e113 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.4324f856cd32e113"
    cluster         = "k26bb.4324f856cd32e113"
    cluster_size    = "26"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "virut malicious virtob"
    md5_hashes      = "['36f7bfe3bf57e98528f2c72462bcf0c5255ca81d','69c6258de5a0c7fbbeb54b16eee1633565affb1d','9b22cb3eb95cd08b20395c76372dfd65a34762fd']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.4324f856cd32e113"

  strings:
    $hex_string = { 66 39 02 74 05 42 42 4e 75 f6 3b f0 75 07 b8 57 00 07 80 eb 0b 8b 55 10 3b d0 74 04 2b ce 89 0a 5e 5d c2 0c 00 cc cc cc cc cc 8b ff 55 8b ec 56 8b 75 08 56 ff 15 54 10 00 01 66 83 3e 22 75 21 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}