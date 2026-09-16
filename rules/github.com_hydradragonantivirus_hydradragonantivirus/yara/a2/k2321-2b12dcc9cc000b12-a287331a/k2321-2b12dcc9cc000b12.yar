rule k2321_2b12dcc9cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2b12dcc9cc000b12"
    cluster      = "k2321.2b12dcc9cc000b12"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "rincux ddos stormattack"
    md5_hashes   = "['06e88b8f2fdb03ed2c3d92a507d2dfae','14fe481234f51443522b9b7072de670c','76f05f590a58b4f9b2832a33e222e18d']"

  strings:
    $hex_string = { 20 f6 1f 84 a9 56 c2 8a a6 70 64 25 fb 80 30 0b 63 4a 04 1d 2a d9 74 3b d8 eb 94 f8 aa 60 8b 02 d3 d0 12 d8 41 1b ac 61 65 10 66 1c b7 08 55 b0 29 a1 ad 78 25 3b ca 67 e4 6a e2 23 cc b1 73 93 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}