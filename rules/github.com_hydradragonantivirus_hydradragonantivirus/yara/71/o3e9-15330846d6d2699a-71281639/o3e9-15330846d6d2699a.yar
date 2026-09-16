rule o3e9_15330846d6d2699a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.15330846d6d2699a"
    cluster      = "o3e9.15330846d6d2699a"
    cluster_size = "530"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['006dac68b62ec59acaebadaeb93ff835','007607761c2f4f4316dadee80afdd287','04de904f819634e72eeed0ed2ecb305d']"

  strings:
    $hex_string = { b6 18 12 41 f1 a9 61 79 9d 06 47 50 59 ab 85 3b 3c 4d 84 5f 69 19 18 2c de 7a 03 91 2d be 72 2b 9a 30 48 8f f8 d3 07 bd 1d 1b 21 9b 66 f7 1e 93 52 b6 c7 ca d6 c9 7c e9 dc 32 62 c6 7d b5 0d b3 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}