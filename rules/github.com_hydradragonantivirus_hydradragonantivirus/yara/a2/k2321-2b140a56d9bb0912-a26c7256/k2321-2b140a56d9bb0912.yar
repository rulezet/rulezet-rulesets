rule k2321_2b140a56d9bb0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2b140a56d9bb0912"
    cluster      = "k2321.2b140a56d9bb0912"
    cluster_size = "27"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ganelp autorun emailworm"
    md5_hashes   = "['10dcc02d870b09ac9820ddb1e12691d0','25188058f222fdbe37eaaf1021c0e793','b1abee3d800e07eaa09c42b8beb00734']"

  strings:
    $hex_string = { ad ed 6d c5 bc 03 dd 5e 10 5a c9 94 79 57 f7 22 a9 b3 e1 75 98 3c dc 56 7b 07 cb 20 06 95 08 82 60 b6 b5 0c a2 c9 9e 26 18 33 83 a7 5b bb a1 9a 86 d8 e5 49 37 2d 2c 4d c0 93 24 76 5d 5c 04 13 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}