rule p3f1_111aa54bc6220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3f1.111aa54bc6220b12"
    cluster      = "p3f1.111aa54bc6220b12"
    cluster_size = "24"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "generickd triada androidos"
    md5_hashes   = "['0dfd54d6c78b9b5951d7987c74ae65bc','14d60fe93d90b74e0bc7e320e9055fe2','a5965f19d121b1a621cbfb45cab2f735']"

  strings:
    $hex_string = { bf fc ba 78 95 c0 b4 08 fe 7c 06 7f ff de 23 e7 a4 f5 1a 2b bd 25 91 7e 50 48 5f 77 aa f8 dc d6 8a ee e2 7a 6e b6 d4 3b b7 82 a9 e4 9c cc 15 63 26 6b 75 19 d3 c2 14 f1 57 cd c8 52 c1 3d 17 fa }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}