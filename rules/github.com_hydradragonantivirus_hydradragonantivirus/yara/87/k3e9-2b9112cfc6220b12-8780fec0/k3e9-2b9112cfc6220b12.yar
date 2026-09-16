rule k3e9_2b9112cfc6220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2b9112cfc6220b12"
    cluster      = "k3e9.2b9112cfc6220b12"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre trojandownloader dmid"
    md5_hashes   = "['1511847e54ee256cd93fb455c701eb22','355d04faae55adca4d6d25528a8d8fe9','c4fcd44ff25b6abfac7ebfa86eb24d14']"

  strings:
    $hex_string = { 03 66 ae a5 ec 37 62 3b 77 f0 28 48 b2 d0 26 23 5d 66 ac 6e 12 a4 7c a6 5b dc d7 f4 6e 07 1c c2 c9 a2 6c 81 7a 04 e5 29 41 a9 e3 95 e7 8d c1 15 c7 78 72 ea 54 a0 ee d1 05 2d 75 0b 16 e8 cf 33 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}