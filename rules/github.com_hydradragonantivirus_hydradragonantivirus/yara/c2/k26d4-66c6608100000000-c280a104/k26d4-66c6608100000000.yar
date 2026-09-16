rule k26d4_66c6608100000000 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26d4.66c6608100000000"
    cluster         = "k26d4.66c6608100000000"
    cluster_size    = "148"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "mywebsearch malicious toolbar"
    md5_hashes      = "['5665e932467d9130c9d067238e18a04183ae6e61','ed8cfd93fdcca5be81fb29ce8ea132ea24ad6041','3a59df1cf23a108169bd76d20e1672e74a1e52f4']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26d4.66c6608100000000"

  strings:
    $hex_string = { 74 24 0c 73 0d 8b 06 85 c0 74 02 ff d0 83 c6 04 eb ed 5e c3 a1 c8 30 00 10 85 c0 74 2f 8b 0d c4 30 00 10 56 8d 71 fc 3b f0 72 12 8b 0e 85 c9 74 07 ff d1 a1 c8 30 00 10 83 ee 04 eb ea 50 e8 4f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}