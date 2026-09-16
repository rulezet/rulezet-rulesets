rule k3e9_119c9cc9cc000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.119c9cc9cc000b32"
    cluster      = "k3e9.119c9cc9cc000b32"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vilsel pworm smck"
    md5_hashes   = "['097d8ee3bf9de1274e3da17ba87c06bb','1c1636088626de9fe32ce4a9b514c921','a4983ba12e0cfbd012f39294050c1934']"

  strings:
    $hex_string = { 3d 33 da 00 59 f2 d1 7e 29 14 a3 9f eb 31 6e 7e 57 43 a4 a9 b1 49 d4 40 92 af d0 50 9e 6e ea c5 4d 37 87 69 c1 7c dd cd f5 76 b2 77 5e 86 6b be bb f0 de 26 3e 4b e4 e5 5f 46 cf ba 79 3b fe 66 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}