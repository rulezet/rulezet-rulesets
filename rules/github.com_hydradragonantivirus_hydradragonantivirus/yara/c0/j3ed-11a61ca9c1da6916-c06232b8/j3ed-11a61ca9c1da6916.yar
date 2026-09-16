rule j3ed_11a61ca9c1da6916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3ed.11a61ca9c1da6916"
    cluster      = "j3ed.11a61ca9c1da6916"
    cluster_size = "7"
    filetype     = "PE32 executable (DLL) (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ursu malicious proxy"
    md5_hashes   = "['0c87c7b6f54d62750fcb7f18dbc60f09','3d44116b4400d4250d4e0afefded1fa2','dfface1e42dc68fabe001d8749851238']"

  strings:
    $hex_string = { d1 52 ba 64 43 b2 5c b8 ce 51 00 10 40 89 10 b2 66 86 d6 88 70 04 b2 61 86 d6 88 70 08 51 b9 2a 19 75 17 87 d1 29 10 59 8b 15 2e 11 00 10 28 50 06 5a eb 05 eb 62 ff d0 c3 53 56 57 5b bf a0 5d }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}