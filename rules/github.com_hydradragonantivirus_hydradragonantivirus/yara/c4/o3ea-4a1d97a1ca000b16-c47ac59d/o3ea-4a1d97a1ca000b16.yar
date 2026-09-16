rule o3ea_4a1d97a1ca000b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3ea.4a1d97a1ca000b16"
    cluster      = "o3ea.4a1d97a1ca000b16"
    cluster_size = "1271"
    filetype     = "application/java-archive"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androidos riskware smspay"
    md5_hashes   = "['003f469795a474d8386d62a5aeedb1d9','004988a365429bdf77c3a859c0e0bc7e','02bf336c858536dcded3687742d08869']"

  strings:
    $hex_string = { c8 71 3a 18 58 dc 0a 4f 56 cb fe 1b af 3e a1 99 c5 61 f3 c6 bb 34 d6 3f 51 76 12 ad 94 aa e2 11 e7 70 31 8a d2 44 b4 9b 62 91 7b c0 37 79 4a a3 f0 02 8b 4d 78 a8 86 25 13 cc 8d 08 ba 9a 39 65 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}