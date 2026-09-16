rule ofc8_5914a2cbc6220b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.5914a2cbc6220b12"
    cluster         = "ofc8.5914a2cbc6220b12"
    cluster_size    = "8"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smspay riskware shedun"
    md5_hashes      = "['2a0cfe7d83d49c19addb885070dcf76dc687d91b','0a4f94a2774486006160e362e01e917cdc32c89a','adc0e36316f6e97b3c41153508c3c2fd72d87b47']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.5914a2cbc6220b12"

  strings:
    $hex_string = { 96 47 1a 09 2c c3 d6 c2 d5 ed c4 56 dd 60 10 98 8f bb b1 4c be 80 93 db c9 ae 26 a3 20 df 46 e0 0b f3 5e 0c 0f 71 6d 77 37 e5 7c 97 7d 94 a6 a9 63 c8 f4 ab 36 fa ec 2a 8d 25 7b 3f 57 28 0a bc }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}