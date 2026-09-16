rule k3e9_0b1af3a9c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0b1af3a9c8000b12"
    cluster      = "k3e9.0b1af3a9c8000b12"
    cluster_size = "355"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "bqbqxwpi injector backdoor"
    md5_hashes   = "['0103ae7123175ab5423bdd3ad188d7e0','01d7483a10e1d655c3c4cd89fded0374','1879701a442e3ba17712df66133b4094']"

  strings:
    $hex_string = { 57 54 8d 51 d4 7d 4f 34 81 e8 6c fe ac ad 4a a9 f9 87 06 51 de 28 04 1a 3a 53 99 10 64 42 a3 69 a0 90 49 0c 26 8a 12 05 17 21 8d 00 08 74 e3 a5 a4 32 91 44 65 d0 19 2b 62 2e c0 8c 7f 89 fa d6 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}