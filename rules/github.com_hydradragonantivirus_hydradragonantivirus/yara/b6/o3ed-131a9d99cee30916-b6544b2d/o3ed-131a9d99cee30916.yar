rule o3ed_131a9d99cee30916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3ed.131a9d99cee30916"
    cluster      = "o3ed.131a9d99cee30916"
    cluster_size = "1154"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit nimnul bqjjnb"
    md5_hashes   = "['00de1aba083f34e4eaa5b7a8a4b8548f','015871d3fc6a3235b6344fcd9661b3f0','09dd10fe01097bd639dcfe8172654116']"

  strings:
    $hex_string = { ca 0f bf c9 2b cb 03 f1 40 50 ff 15 90 81 17 08 59 89 45 e4 83 fe 09 7e 12 6a 09 5e 8d 44 3d e8 80 3c 30 30 75 05 4e 85 f6 7f f5 2b 75 e4 79 04 33 c0 eb 02 8b c6 8b 4d fc 5f 5e 33 cd 5b e8 5a }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}