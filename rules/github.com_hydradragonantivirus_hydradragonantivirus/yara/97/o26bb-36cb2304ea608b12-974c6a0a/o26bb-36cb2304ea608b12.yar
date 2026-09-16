rule o26bb_36cb2304ea608b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.36cb2304ea608b12"
    cluster         = "o26bb.36cb2304ea608b12"
    cluster_size    = "83"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "dangerousobject dangeroussig eksktak"
    md5_hashes      = "['af2298b33277af2f4688838974b7e4d2611a9e45','72bb9660a934e076f2e43e7f5b33a085718d1bf2','c803bd1b95baa7021038864a06d2a68afc8b07c2']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.36cb2304ea608b12"

  strings:
    $hex_string = { fa 0b 0b 0b 9d 03 03 03 13 a6 00 00 00 00 a5 00 00 00 00 02 01 01 01 0a 08 08 08 76 10 10 10 ee 81 11 11 11 ff 07 12 12 12 ff 14 14 14 ff 15 15 15 ff 16 16 16 ff 18 18 18 ff 19 19 19 ff 1b 1b }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}