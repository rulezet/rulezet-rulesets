rule p26bb_2114418986220b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=p26bb.2114418986220b12"
    cluster         = "p26bb.2114418986220b12"
    cluster_size    = "5"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "nymeria malicious generickd"
    md5_hashes      = "['c689f048514f049845a251d65a4c540885feceb8','01a2b0152193d81bcf98ecfa19d7bb191e476391','8d066e624ea796dc9f5a835a6992a324cf2975e3']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=p26bb.2114418986220b12"

  strings:
    $hex_string = { 86 9b 00 1a 88 3b 46 11 22 60 d5 c7 9e 82 14 40 48 67 bd c2 27 a7 75 6b 6a 9f 0a d9 89 c1 c0 52 dc e2 9c 41 37 69 cb 6c cc 6d 1c 64 0c 7d ed a1 58 b0 b8 49 f8 29 c5 39 e0 57 2b b9 0f d0 de aa }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}