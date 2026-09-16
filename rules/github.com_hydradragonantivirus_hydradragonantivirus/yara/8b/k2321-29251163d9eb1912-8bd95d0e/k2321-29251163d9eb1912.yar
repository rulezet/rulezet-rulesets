rule k2321_29251163d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.29251163d9eb1912"
    cluster      = "k2321.29251163d9eb1912"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus vbkrypt symmi"
    md5_hashes   = "['6d148b8b708e6610c1e840c13f25cde5','80105799f70939f2e05cd87bb9e62604','f239a59f77cc8b8432fbfea317a33b8f']"

  strings:
    $hex_string = { 17 a1 e3 18 5e 7b 46 41 1b d4 c5 3e a0 4d d1 0b 6b 6c 84 db a5 c3 f6 82 c9 30 ac 5d 15 e1 03 2a cd 00 a6 79 4a ad c7 41 e0 12 d7 e4 0d 29 54 5a 92 77 9e 67 c4 76 6c 07 bb 32 3d 21 b6 35 13 ec }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}