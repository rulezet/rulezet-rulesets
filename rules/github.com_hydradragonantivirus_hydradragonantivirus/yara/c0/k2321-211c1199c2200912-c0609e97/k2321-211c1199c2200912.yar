rule k2321_211c1199c2200912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.211c1199c2200912"
    cluster      = "k2321.211c1199c2200912"
    cluster_size = "20"
    filetype     = "PE32 executable (console) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "hackkms hacktool kmsactivator"
    md5_hashes   = "['0af1ce466d8990ac22f96fa815435581','10091d584394d4661f7ee3a8e8f97a63','d2ae6e8d97f9ec75c31f1a85a7cd2b1d']"

  strings:
    $hex_string = { 5e 89 ce dd 0c 4c 55 4f f4 4d c4 52 3b d5 96 0d bf 05 9f b7 09 53 2b 0f 42 38 34 e3 27 fc 29 bb b4 71 78 86 b2 d2 a2 0d ee 33 8b 20 f1 5b 6f 7f 54 a0 f6 8d 3e 1a 9b 63 46 b1 bd d3 4b 6e b9 82 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}