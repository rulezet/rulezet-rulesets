rule o3e9_019c90b9c8800b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.019c90b9c8800b32"
    cluster      = "o3e9.019c90b9c8800b32"
    cluster_size = "13"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "miniduke backdoor cosmicduke"
    md5_hashes   = "['08aba4284937433f8563cb349c28c255','23e504e3f5be20dee72765da1d648db4','fec0d9f78be3e403d1dcf62a74a6508e']"

  strings:
    $hex_string = { 9c c8 ec 30 38 8c c7 1f 42 ee 63 66 37 2d de 28 f6 cb 7c 60 e8 87 c4 d6 2f f5 8a 70 29 14 cf b9 e2 71 88 22 15 cc fe 51 48 ab 2c 3c ca 6b 21 08 d8 8e 0e c6 64 7d 7f 7e 97 f0 49 59 97 03 9e ad }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}