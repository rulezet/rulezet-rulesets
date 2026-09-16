rule k26c0_19996bbcc2000932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26c0.19996bbcc2000932"
    cluster         = "k26c0.19996bbcc2000932"
    cluster_size    = "3"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "ursu malicious clipspy"
    md5_hashes      = "['c7b8bf4a86b826686a7e9b439fcafd025a4e955b','4cc6a6054e836039db8f77066fa6d2834d1228eb','c80133825c975c5003defa472dd77756aceacaaa']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26c0.19996bbcc2000932"

  strings:
    $hex_string = { 0f b6 13 80 fa 2a 74 f5 31 c0 84 d2 74 d5 8b 7c 24 14 81 cf 00 00 01 00 eb 0c 8d 76 00 83 c6 01 80 7e ff 00 74 bd 89 f9 89 f2 89 d8 e8 0c ff ff ff 85 c0 75 e8 83 c4 2c 5b 5e 5f 5d c3 0f be 57 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}