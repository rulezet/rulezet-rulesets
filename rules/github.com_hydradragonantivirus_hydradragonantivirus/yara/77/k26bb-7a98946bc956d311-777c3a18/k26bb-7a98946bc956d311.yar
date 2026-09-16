rule k26bb_7a98946bc956d311 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.7a98946bc956d311"
    cluster         = "k26bb.7a98946bc956d311"
    cluster_size    = "14"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "ursu browsefox malicious"
    md5_hashes      = "['fbcd6f572d39bb4283818741ecb54ed4c4b114ec','d27f1d1d0d253aaf7699d10231a1a0806f7f6a27','31f6bcc16ed9b0f6fb24d7f55b99976659c63c48']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.7a98946bc956d311"

  strings:
    $hex_string = { 53 ff 15 28 91 40 00 5f 5e 5d 5b 59 c3 68 d4 a8 40 00 83 c0 0a 50 e8 22 0a 00 00 8b c8 85 c9 74 a8 8d 14 37 03 ea 3b d1 76 0c 2b ea 8a 02 88 04 2a 4a 3b d1 77 f6 8b 6c 24 1c 2b cf 41 eb 8c 51 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}