rule n3f8_5242e408c0000b10 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=n3f8.5242e408c0000b10"
    cluster         = "n3f8.5242e408c0000b10"
    cluster_size    = "9"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "androidos banker boogr"
    md5_hashes      = "['e0459369bb0088537673b14a2294082aa8aa4988','c311ebcc4fc76dc1c93a7795132840edf3292101','f3f3c0ffa793d1406895995e6128aa095db0d06c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=n3f8.5242e408c0000b10"

  strings:
    $hex_string = { 16 3b 20 70 6f 72 74 20 69 73 20 6f 75 74 20 6f 66 20 72 61 6e 67 65 00 56 3b 5c 73 2a 28 3f 3a 28 5b 61 2d 7a 41 2d 5a 30 2d 39 2d 21 23 24 25 26 27 2a 2b 2e 5e 5f 60 7b 7c 7d 7e 5d 2b 29 3d }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}