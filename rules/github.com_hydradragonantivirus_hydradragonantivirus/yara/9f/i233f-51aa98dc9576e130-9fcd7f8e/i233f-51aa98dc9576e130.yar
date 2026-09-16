rule i233f_51aa98dc9576e130 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=i233f.51aa98dc9576e130"
    cluster         = "i233f.51aa98dc9576e130"
    cluster_size    = "6"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "voiv expkit html"
    md5_hashes      = "['c31d5b7db6c13ede1537096ac81c2f29c28edaf4','6f0f9b058bf9005654636629d47e31808e1cef1a','4cdc486ce694c34664e37f896d70d8a0a9097b76']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=i233f.51aa98dc9576e130"

  strings:
    $hex_string = { 00 2e 00 30 00 22 00 20 00 65 00 6e 00 63 00 6f 00 64 00 69 00 6e 00 67 00 3d 00 22 00 55 00 54 00 46 00 2d 00 31 00 36 00 22 00 3f 00 3e 00 0d 00 0a 00 3c 00 54 00 61 00 73 00 6b 00 20 00 76 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}