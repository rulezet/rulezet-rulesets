rule k3e9_0998dcc9cc000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.0998dcc9cc000912"
    cluster      = "k3e9.0998dcc9cc000912"
    cluster_size = "6"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "rincux ddos stormattack"
    md5_hashes   = "['41f9e42131a93d4356a907880df46114','448b8849e3a1b56d69dab3ddef3dfb35','d5e26c25515b8947e177c616a065e9c0']"

  strings:
    $hex_string = { cb cd 20 fb ba 54 bd 7e 09 fe d3 3c 60 ad 37 5b ec db 74 4b b4 38 56 5e 0a f0 b3 dc 82 15 b9 ab 34 45 1c bb 5a c3 e5 2c 67 65 7a 30 cc d4 5c 90 e9 9f 6b b7 3f 64 35 67 32 78 24 52 63 de 56 07 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}