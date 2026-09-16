rule k26bb_528aec69c8000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.528aec69c8000b32"
    cluster         = "k26bb.528aec69c8000b32"
    cluster_size    = "10"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "virtob malicious virut"
    md5_hashes      = "['bb034fa5a1b81bf663137ff5565e50cbb6428869','75e9a567759e8457cae48ce6d4fc1ab79006eb00','de62e526d29437f44e59851a9525b51ccd00b686']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.528aec69c8000b32"

  strings:
    $hex_string = { 00 01 f7 d6 89 35 88 60 00 01 5e 5f 5b c9 c3 be 4f e6 40 bb eb e6 90 90 90 90 90 8b ff 55 8b ec 56 8b 75 08 33 c0 3b 75 0c 73 11 85 c0 75 0d 8b 0e 85 c9 74 02 ff d1 83 c6 04 eb ea 5e 5d c3 b8 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}