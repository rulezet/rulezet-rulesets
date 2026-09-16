rule k26bb_03d39e98ca210932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26bb.03d39e98ca210932"
    cluster         = "k26bb.03d39e98ca210932"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "browsefox malicious yontoo"
    md5_hashes      = "['f97ba0cddfd72ef5c7d7a42af5778cbb86bddecb','33a177028afba6e675340fc15a8e80ff5c2e3a5a','8625eedae33ddeffb697f93ec263ef45b8b53c22']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26bb.03d39e98ca210932"

  strings:
    $hex_string = { d9 ec 59 d1 6d e6 ce 03 82 f8 19 3e d6 2b 91 87 db 10 de b6 95 5a a4 66 0b f5 5d d8 80 c5 b3 a7 f1 cb 97 7c c7 a5 b0 57 81 5d 8d d2 58 7f 71 c6 37 2f bc 6e df ae 23 2e f6 46 31 77 1f f9 8a 76 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}