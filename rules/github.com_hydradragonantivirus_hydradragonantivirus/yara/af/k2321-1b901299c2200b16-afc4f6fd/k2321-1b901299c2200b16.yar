rule k2321_1b901299c2200b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.1b901299c2200b16"
    cluster      = "k2321.1b901299c2200b16"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "small generickd upatre"
    md5_hashes   = "['4fe57e4e9518948b581afec2e5068b9d','678c5a4c26311db640b1bb8a02b4e9cf','f998967f25a4714a3cd330764cda6e3d']"

  strings:
    $hex_string = { ef 72 e3 84 1d bf fd 0e b3 2e df c9 e1 ee d0 38 18 74 d0 b7 a3 49 4d 73 e2 48 71 1e 7e dd 29 43 05 dc 69 a2 20 83 6c 47 f0 e8 01 44 59 6b 08 eb 3c b2 82 36 c5 f5 4b ae 23 c9 4a 92 42 da c7 9e }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}