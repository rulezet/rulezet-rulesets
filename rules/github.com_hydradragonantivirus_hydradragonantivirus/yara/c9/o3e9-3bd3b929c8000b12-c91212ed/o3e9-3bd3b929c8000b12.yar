rule o3e9_3bd3b929c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.3bd3b929c8000b12"
    cluster      = "o3e9.3bd3b929c8000b12"
    cluster_size = "23"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy malicious qjwmonkey"
    md5_hashes   = "['0520fbd28a99448f7cb2cb386364be6e','130c0457a641de479d88fc122b8d6855','c8e18aaffaaec0e0d6fe0cdab86906ba']"

  strings:
    $hex_string = { fa b8 93 da 1d 79 ec 60 dd 42 d8 bb ba 43 26 b2 a0 4d c7 02 bd 76 21 0e 9a b6 d1 8c 9d b1 83 57 40 e3 2e 3c 9b b5 6d 44 e1 94 61 cc 71 8e 5c 50 54 a4 1c f7 16 fe e3 11 d6 66 0f 7a b3 2f a2 63 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}