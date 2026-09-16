rule o3e7_14935898dee31912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e7.14935898dee31912"
    cluster      = "o3e7.14935898dee31912"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "malicious installmonstr engine"
    md5_hashes   = "['46de2da99e0400ca2296e41932175c0b','ac05f06a0c8c0d2ae3dd13eb9e5a135f','f7b4bbcfe2c9d8c67726eeebf3d84124']"

  strings:
    $hex_string = { 3a bb 3e d7 c6 8b 65 50 ef 9a e7 11 9d 07 b0 74 5c 27 c7 bd 2a 1c a8 2c e4 14 62 0c 18 aa 33 60 5b 31 97 a6 f1 e1 09 f8 22 fa ac 72 35 29 b8 fa f2 2b 90 0e 6c d9 e8 a4 79 e5 8c 1b 13 03 20 67 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}