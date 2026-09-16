rule k2321_0b164a12d9bb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0b164a12d9bb0b12"
    cluster      = "k2321.0b164a12d9bb0b12"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ganelp autorun emailworm"
    md5_hashes   = "['57cfd9a21609d29beb16a9521c749aa4','61d2ee910f51f79d25041e6cac07c488','fd7f341752206f71cdd2043e771c3848']"

  strings:
    $hex_string = { 45 d0 01 26 5a fa 05 8a 40 d5 da 75 31 13 f1 10 59 6f ea 63 8f e8 3f 4d 53 2a 47 b5 7a 71 1a 66 83 5d e3 b6 e0 97 22 30 2b cb af 4e 17 d9 9c a7 6c 28 64 4b 66 12 1f 90 74 04 df 77 9d cd c4 88 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}