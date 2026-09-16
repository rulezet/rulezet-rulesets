rule k26bb_7ab242d292bb3916 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.7ab242d292bb3916"
    cluster         = "k26bb.7ab242d292bb3916"
    cluster_size    = "237"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "defaulttab bundler malicious"
    md5_hashes      = "['b18903d0086d38c3adac30293d3532a217a17ea1','aca9dce8f3adb2a6f8e3c187c1e152ca943ea817','0789b318eb72379e3b8f4f897952a291e6e6daae']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.7ab242d292bb3916"

  strings:
    $hex_string = { 01 99 91 84 05 9d 95 8a 2d c2 bd b5 8f e0 dd d9 d1 f4 f3 f2 fb f5 f5 f3 ff b9 d3 c5 ff a0 db c3 ff a0 db c2 ff b3 cd be ff eb e9 e8 ff ec e9 e9 fd d8 d5 d0 d3 bf b9 b2 91 a0 98 8b 2f 9a 92 85 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}