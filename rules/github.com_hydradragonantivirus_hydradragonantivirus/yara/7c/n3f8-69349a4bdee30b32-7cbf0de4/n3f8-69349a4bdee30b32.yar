rule n3f8_69349a4bdee30b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.69349a4bdee30b32"
    cluster         = "n3f8.69349a4bdee30b32"
    cluster_size    = "21"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "droidkungfu androidos kungfu"
    md5_hashes      = "['9e674bb9b854eae228be862fcad01e8ea129a85a','c55076add622aae781c6a63122af088699151a0f','da5d56e29466f675528ee59d79b6cf351a69e9fb']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.69349a4bdee30b32"

  strings:
    $hex_string = { 01 47 03 4e 10 00 00 2c 01 46 02 57 10 00 00 2c 01 7c 03 a2 10 00 00 2e 01 05 02 4a 01 00 00 2e 01 a2 02 67 0d 00 00 2e 01 a0 02 f2 0f 00 00 2f 01 a3 02 4a 01 00 00 2f 01 2a 02 3b 0e 00 00 30 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}