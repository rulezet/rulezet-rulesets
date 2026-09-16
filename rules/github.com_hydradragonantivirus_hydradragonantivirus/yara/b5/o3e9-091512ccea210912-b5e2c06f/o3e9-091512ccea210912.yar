rule o3e9_091512ccea210912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.091512ccea210912"
    cluster      = "o3e9.091512ccea210912"
    cluster_size = "11"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "unwanted crawler webtoolbar"
    md5_hashes   = "['0f9c72b5903868182bffd2c1c64e8c53','2e9ad203adb4841a95fbb273eec19e25','f885df1dc7304d22bcf6a803ca95c263']"

  strings:
    $hex_string = { cc 69 3c 1e 25 b9 58 b2 e7 f3 51 c3 77 49 15 48 30 b3 aa cf 3f 3b b7 0f 4f c6 ae 99 db 38 20 a6 9d ea 8c 52 e1 fa 86 ef 92 bc 0d 84 fd 6b 5d a3 ed dd 9a 4e 34 10 2c d5 fe 4d c0 07 5e e9 55 64 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}