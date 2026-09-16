rule n3f1_491e929dc6220b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.491e929dc6220b32"
    cluster      = "n3f1.491e929dc6220b32"
    cluster_size = "17"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "obfus androidos andr"
    md5_hashes   = "['107e187dc5e9d318170b54e429300b65','1636f7a1c078505fe3328fef212d4c51','f6b8eeef3b0eb93217db599c1212fc71']"

  strings:
    $hex_string = { 13 ec a8 78 67 2d 50 19 87 aa 36 73 c7 ff 7b f7 ee c5 1b de f0 7a 48 dd 0f c2 5e b5 2f a4 09 15 8c d6 41 0a 05 53 5b 98 da c2 1a 86 ef 9d 12 f8 fc e7 ff 71 2e 88 70 3a ad 90 e5 39 a6 55 1d ea }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}