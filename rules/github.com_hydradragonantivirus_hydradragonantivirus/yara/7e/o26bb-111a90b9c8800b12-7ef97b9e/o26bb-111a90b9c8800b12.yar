rule o26bb_111a90b9c8800b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.111a90b9c8800b12"
    cluster         = "o26bb.111a90b9c8800b12"
    cluster_size    = "16"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "ezxank malicious dangerousobject"
    md5_hashes      = "['3c81875abb78a9ce0f099015cd5c762ea6e936a3','f4524e3f7d5f041d6c5388bb8469a54bf8b46248','9713a5fb455f27b56cfff1e96cfa614bd643ef8b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.111a90b9c8800b12"

  strings:
    $hex_string = { c0 46 fa 78 84 d3 28 5b 08 64 1c 30 7e 05 c2 09 a1 55 be ac 53 c8 e7 9e b7 01 ad 24 e5 10 e3 ec 47 e1 31 a9 0a 7c 89 65 a5 ee 26 22 41 c1 00 d1 96 d5 18 57 6a c9 99 ba d7 bb 21 95 b1 77 7f c5 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}