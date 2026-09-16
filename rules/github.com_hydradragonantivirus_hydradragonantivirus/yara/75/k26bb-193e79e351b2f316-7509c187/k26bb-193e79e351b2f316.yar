rule k26bb_193e79e351b2f316 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.193e79e351b2f316"
    cluster         = "k26bb.193e79e351b2f316"
    cluster_size    = "295"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "installcore unwanted dealply"
    md5_hashes      = "['65cd13ab8d937ab5543c48f19805983af88a5e17','2f61396d7daf422ba97a191c30bff9aa40dbeea9','50cda02ab2ef74503a6458633f5d9279a31e414a']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.193e79e351b2f316"

  strings:
    $hex_string = { 61 20 69 73 20 63 6f 72 72 75 70 74 65 64 20 28 25 64 29 00 00 53 83 c4 f8 8b d8 89 1c 24 c6 44 24 04 0b 54 6a 00 b9 18 7e 40 00 b2 01 b8 c8 77 40 00 e8 be da ff ff e8 a9 b0 ff ff 59 5a 5b c3 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}