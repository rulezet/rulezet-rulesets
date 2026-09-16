rule n3f8_7d96a499c2200932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.7d96a499c2200932"
    cluster         = "n3f8.7d96a499c2200932"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "fakeinst androidos decrypter"
    md5_hashes      = "['7a83d89f029585cb60f7694eb9200647ff8c7e6b','66a59a28ba4a53452e100ea21c10a9a866d64ef0','44f34c86c505c0f518d8848051f89fd1547ac7a1']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.7d96a499c2200932"

  strings:
    $hex_string = { 21 00 00 2a 02 55 00 d6 1c 00 00 2b 02 64 07 6a 0f 00 00 2c 02 60 07 c1 1d 00 00 2d 02 c8 06 0a 22 00 00 2e 02 64 07 58 03 00 00 2e 02 8b 07 49 39 00 00 30 02 32 02 31 3e 00 00 33 02 34 02 6d }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}