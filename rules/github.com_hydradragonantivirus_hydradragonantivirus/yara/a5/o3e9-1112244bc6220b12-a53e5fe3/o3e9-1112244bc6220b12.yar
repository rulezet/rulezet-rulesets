rule o3e9_1112244bc6220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.1112244bc6220b12"
    cluster      = "o3e9.1112244bc6220b12"
    cluster_size = "413"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmetrix installmonster bundler"
    md5_hashes   = "['015d9d835b51b04cac7b6cbe9f686666','021b7f49e504fb68bdd72b5aaaaf9f1b','0c3d1a180b53acddf5afda34713ea116']"

  strings:
    $hex_string = { f9 31 b8 f5 01 ea fa d1 9c 6c e7 26 ad e0 34 bd f0 00 03 cb 42 0f f7 7c 32 76 ff ba 7e f3 b6 5a 0a e2 73 65 9d 62 e9 a4 5c 77 3a ca 41 46 15 7f 6b 3a b1 fc 08 23 6e 82 d3 2c 59 a9 22 ed 12 67 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}