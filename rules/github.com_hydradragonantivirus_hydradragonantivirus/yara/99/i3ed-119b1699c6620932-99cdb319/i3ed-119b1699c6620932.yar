rule i3ed_119b1699c6620932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3ed.119b1699c6620932"
    cluster      = "i3ed.119b1699c6620932"
    cluster_size = "4"
    filetype     = "PE32 executable (DLL) (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "padodor backdoor symmi"
    md5_hashes   = "['5f4d6d0085c284964f5a2f6fe28e3952','86744266a07905c2aeb494e806d418da','c5f0f7a0127420807cbf46022cfaf915']"

  strings:
    $hex_string = { 7d 01 0d cb 43 2a 42 f1 fe f3 a5 b2 89 b5 68 21 ee d5 2d 7c 6c 58 78 c2 4d 2c 5c 13 45 e8 84 05 dd 69 af 12 05 75 07 d1 9d 20 c0 09 0a 74 e1 14 99 c6 ad ff d5 97 40 dc 55 ac 41 6b fb 85 79 d6 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}