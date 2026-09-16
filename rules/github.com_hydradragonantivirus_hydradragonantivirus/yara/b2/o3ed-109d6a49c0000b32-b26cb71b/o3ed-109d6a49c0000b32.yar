rule o3ed_109d6a49c0000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3ed.109d6a49c0000b32"
    cluster      = "o3ed.109d6a49c0000b32"
    cluster_size = "64"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ursu pakes avqm"
    md5_hashes   = "['00ba41faaf060352071382ecde03b9b3','00efe2ac4b84319d4a76ed8073339baa','409751d3db7b8e60e3311aa1bc7b0b5a']"

  strings:
    $hex_string = { 47 b7 14 f6 82 1b 4c 1c c7 0b 3a 36 22 56 c4 20 66 9c 98 21 a2 9d 13 11 53 4e 43 60 ed c6 df a7 00 94 72 86 1f 40 24 89 90 93 ce 33 49 2d 64 cf 83 27 68 45 58 e0 36 18 8c 2f b4 10 c9 2e 1c 6f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}