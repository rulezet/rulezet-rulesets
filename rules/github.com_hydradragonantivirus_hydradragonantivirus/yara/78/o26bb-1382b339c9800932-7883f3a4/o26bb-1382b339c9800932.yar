rule o26bb_1382b339c9800932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.1382b339c9800932"
    cluster         = "o26bb.1382b339c9800932"
    cluster_size    = "34"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "graftor dangerousobject fraudload"
    md5_hashes      = "['748ed850fe30e31459ce0c4e371d0f9beef88909','aeb27828671e087bd19061e45a859ef0254a8921','767eeae5e18a65f68f360b4cc10d3a433ad62dab']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.1382b339c9800932"

  strings:
    $hex_string = { cd e0 e6 ec e8 f2 e5 20 f7 f2 ee e1 fb 20 f3 e2 e8 e4 e5 f2 fc 20 ee f0 e8 e3 e8 ed e0 eb 22 01 00 01 0a 49 64 65 6e 74 69 66 69 65 72 06 21 6d 5f 70 42 74 6e 56 69 65 77 53 6f 75 72 63 65 2e }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}