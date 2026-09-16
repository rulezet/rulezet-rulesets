rule k26bb_4b366da1c4000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.4b366da1c4000b12"
    cluster         = "k26bb.4b366da1c4000b12"
    cluster_size    = "12"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "virut malicious patched"
    md5_hashes      = "['1bb44a330eaa2dcd6c3c3be79a017b4ec0280be3','73d4c9e9cc6a0cbe7df27d06fa63edcc07d57394','72e9baa173fb358e79a3b7e948c6b30a100ee555']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.4b366da1c4000b12"

  strings:
    $hex_string = { 39 02 74 05 42 42 4e 75 f6 3b f0 75 07 b8 57 00 07 80 eb 0b 8b 55 10 3b d0 74 04 2b ce 89 0a 5e 5d c2 0c 00 cc cc cc cc cc 8b ff 55 8b ec 56 8b 75 08 56 ff 15 58 10 00 01 66 83 3e 22 75 21 66 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}