rule o26bb_0cfa3dc9c6200912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bb.0cfa3dc9c6200912"
    cluster         = "o26bb.0cfa3dc9c6200912"
    cluster_size    = "45"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "kuzitui kuaizip kzip"
    md5_hashes      = "['376e3409e26b9e7669a5a39545aa5dfb115cad91','2ee27afad7c286934e4511952d06c0b88fbdea20','c4819ffb3d7f252204185b5efa35ad70d8ec969c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bb.0cfa3dc9c6200912"

  strings:
    $hex_string = { 78 55 49 40 44 75 69 4c 69 62 40 40 51 41 45 58 48 48 50 41 55 74 61 67 52 45 43 54 40 40 50 42 5f 57 40 5a 00 3f 4f 6e 4d 6f 75 73 65 48 6f 76 65 72 40 57 69 6e 64 6f 77 49 6d 70 6c 42 61 73 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}