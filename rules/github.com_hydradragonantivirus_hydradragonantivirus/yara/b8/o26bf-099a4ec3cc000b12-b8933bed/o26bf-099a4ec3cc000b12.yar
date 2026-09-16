rule o26bf_099a4ec3cc000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bf.099a4ec3cc000b12"
    cluster         = "o26bf.099a4ec3cc000b12"
    cluster_size    = "6"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "temonde malicious adload"
    md5_hashes      = "['546d9edf538a456d14e7cc80cca27c053b383928','0b1de6a0f44ef7b993e2518d72c043f6dc1360f9','3f097d3bc414bb60d11f17f6dc321e449ddb81f4']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bf.099a4ec3cc000b12"

  strings:
    $hex_string = { 00 31 2e 2d b7 a4 9b 97 ff a5 9b 98 fe a6 9c 99 ff 73 6c 6a ff 84 7c 7a ff a3 99 96 fe 23 24 25 c1 06 43 5b 7f 09 64 88 eb 09 68 8c fe 09 6d 90 ff 09 71 94 ff 09 76 99 ff 08 7a 9c fe 08 7e a0 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}