rule o3f8_496e5399c2201132 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o3f8.496e5399c2201132"
    cluster         = "o3f8.496e5399c2201132"
    cluster_size    = "6"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos smssend andr"
    md5_hashes      = "['ead9f6d494eca6184a1d7b6c8200a6815ce0feb8','00525bb848e170adef2ac83aed016d9511ec7b33','b2e1b08e053c289d1a83ff63835a8c42e5cf3c6b']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o3f8.496e5399c2201132"

  strings:
    $hex_string = { b8 8d e8 83 bd e4 b8 ba e7 a9 ba e3 80 82 00 0b 5a 68 61 6e 67 50 61 79 4d 53 46 00 0f 5a 68 61 6e 67 50 61 79 e8 ae a1 e8 b4 b9 e6 8f 90 e7 a4 ba e6 a1 86 e5 90 af e5 8a a8 00 04 5a 6f 70 66 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}