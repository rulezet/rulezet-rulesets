rule k2321_0935a42dda52f936 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0935a42dda52f936"
    cluster      = "k2321.0935a42dda52f936"
    cluster_size = "41"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nimnul vjadtre wapomi"
    md5_hashes   = "['01dcd22619f044d5257eaf0484932953','094c66fd958a76607788b76d1769d28b','76745391d8409f330a24511245e72cd4']"

  strings:
    $hex_string = { 3c 8d fe 5b 24 b3 0d 5d c7 10 da 65 ce b7 1e fa d3 e4 14 3b 3d ad 35 92 dd 2e 33 dd a4 6f 02 67 a5 d6 37 31 db 13 f0 81 1b df af 05 f9 88 79 77 f2 a7 bc 7e 7f a9 80 29 6b 9a 34 e3 cc ed 0c bf }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}