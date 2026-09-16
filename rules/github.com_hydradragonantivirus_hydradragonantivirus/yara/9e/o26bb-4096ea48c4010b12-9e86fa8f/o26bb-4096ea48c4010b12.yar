rule o26bb_4096ea48c4010b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.4096ea48c4010b12"
    cluster         = "o26bb.4096ea48c4010b12"
    cluster_size    = "82192"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "generickdz malicious adposhel"
    md5_hashes      = "['3d286712bf68d0a4164e976011d301a6e268d9b1','d5c666142ef4aa7b3405836ede646210a04ba7f7','5c846d39877c96dfaca39983e25b68a41e8f8401']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.4096ea48c4010b12"

  strings:
    $hex_string = { 45 d8 d4 08 da b9 98 70 4a 63 a7 67 58 44 2e 3e ed 13 30 e4 a5 9e 17 38 5d 57 64 d5 a2 dd 50 b0 d3 39 d6 55 59 fc eb 48 93 3a 22 e1 88 91 99 bd 04 2a 3c 8b fc f6 cc 16 2f 86 41 c4 15 0a b5 62 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}