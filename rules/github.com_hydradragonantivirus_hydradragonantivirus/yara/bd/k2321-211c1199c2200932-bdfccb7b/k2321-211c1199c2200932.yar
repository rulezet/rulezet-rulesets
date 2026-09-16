rule k2321_211c1199c2200932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.211c1199c2200932"
    cluster      = "k2321.211c1199c2200932"
    cluster_size = "22"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "hackkms hacktool kmsactivator"
    md5_hashes   = "['01b433c5dfa47c3aab7350d04fb72c9d','0286e1238f84fdf60f121e076d726ced','826a24cb4b906e1709db25cfae9cc403']"

  strings:
    $hex_string = { 64 ec f8 ad 21 7d d2 c5 90 b2 40 a8 96 33 19 23 e9 44 4a 98 56 bd 06 e2 7a 27 46 2a cc ea ce a9 cd 1f be 38 a2 4d c1 41 5e 5c 5d 0e 42 08 af d0 d6 82 86 75 71 a3 58 69 3d 37 5f 99 de 73 bf 0d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}