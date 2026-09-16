rule j3e9_46b25d8f4e831912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.46b25d8f4e831912"
    cluster      = "j3e9.46b25d8f4e831912"
    cluster_size = "5"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor poison poisonivy"
    md5_hashes   = "['a0cc12affb459d48cfc4dad8764904bf','a38ff2ee39974e8b9048af6810d3107e','d4b39c2c651505f46c988ad7417074b2']"

  strings:
    $hex_string = { 14 58 3a 61 de 1b 11 1c 32 0f 9c 16 53 18 f2 22 fe 44 cf b2 c3 b5 7a 91 24 08 e8 a8 60 fc 69 50 aa d0 a0 7d a1 89 62 97 54 5b 1e 95 e0 ff 64 d2 10 c4 00 48 a3 f7 75 db 8a 03 e6 da 09 3f dd 94 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}