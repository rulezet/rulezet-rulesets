rule pfc8_1b9b8be9c4000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=pfc8.1b9b8be9c4000b12"
    cluster         = "pfc8.1b9b8be9c4000b12"
    cluster_size    = "10"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "aiodownloader androidos apbl"
    md5_hashes      = "['917abc3b46c113eae044325bc9c120d9664f9c93','7691dc79090f4d5b499a8fb94ca186af5fdbb2c5','72060e7e9f32550e871376989598ccbcf11a4058']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=pfc8.1b9b8be9c4000b12"

  strings:
    $hex_string = { e5 e2 08 71 4e 2c ad 60 c6 95 7c 5e 19 7f c8 55 70 72 5c cd 4f 96 46 66 fd d1 b8 1a 62 ae e1 67 09 6a ac 58 32 81 de 41 b7 d2 87 e8 5b dc f6 0a 3f af 0b 48 b6 3d 0c ce ef f4 65 1f 3a da 77 f5 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}