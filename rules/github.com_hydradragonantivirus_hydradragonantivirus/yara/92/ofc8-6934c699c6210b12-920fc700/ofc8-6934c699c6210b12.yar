rule ofc8_6934c699c6210b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.6934c699c6210b12"
    cluster         = "ofc8.6934c699c6210b12"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "riskware smsreg smspay"
    md5_hashes      = "['302b81ef4b47fe4cf36bc6e5747e3f05e1642d84','1a0f8c6d5d78c4fda2bd889153b514fdb1061402','2461ecd1cb03e9f2761a77fb44452388463ce141']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.6934c699c6210b12"

  strings:
    $hex_string = { 2a 95 eb b0 5a e5 aa c9 33 76 e8 af ed 07 92 96 35 ca 4b 40 3f 11 9a 34 7d 38 8d 20 a6 c6 7f 50 ac e6 59 ff 22 25 e0 9c bf 87 cb 7c c7 29 e7 3b ea 66 13 0d 3c 98 1a da a9 9f 44 94 84 bc 68 81 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}