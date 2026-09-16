rule p26bb_039e1cc1cc000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26bb.039e1cc1cc000b12"
    cluster         = "p26bb.039e1cc1cc000b12"
    cluster_size    = "36"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "virlock nabucur polyransom"
    md5_hashes      = "['2e03371bda912a85ddf390646c20fa549b5e48b1','b04d29aed1c7aea9f05274654f20bc985e66b5b3','d191ae3a958a3349c8ac704615524bc968503498']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26bb.039e1cc1cc000b12"

  strings:
    $hex_string = { 00 29 29 29 03 c3 c8 cc 7b a4 6d 58 ff c3 3c 04 ff c4 59 1e ff ca 64 26 ff d0 6a 25 ff d3 72 30 ff e2 9d 73 ff f1 c6 ae ff ec df d6 ff c9 ee f6 ff 9f e5 f5 ff 5f ce ea ff 39 c3 e5 ff 56 cd e7 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}