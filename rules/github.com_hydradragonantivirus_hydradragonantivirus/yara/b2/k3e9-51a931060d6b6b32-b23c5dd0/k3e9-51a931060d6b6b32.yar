rule k3e9_51a931060d6b6b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.51a931060d6b6b32"
    cluster      = "k3e9.51a931060d6b6b32"
    cluster_size = "3"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "chir runouce virut"
    md5_hashes   = "['a9361ece0aaca7b72d9e9473b03320df','cc596ca77f57d27268841780e9236f49','d86fbb99cb0621dc862bb7ce4f63a49a']"

  strings:
    $hex_string = { 33 c0 fc aa 80 fe 01 75 bb 80 fa 01 72 b6 2b fc 83 ff 06 72 af 8a 04 24 3c 40 74 a8 3c 2e 74 a4 54 e8 48 ff ff ff eb 9c fe c2 eb 02 fe c6 8a c1 fc aa eb 94 53 ff 56 40 81 c4 00 01 00 00 61 c9 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}