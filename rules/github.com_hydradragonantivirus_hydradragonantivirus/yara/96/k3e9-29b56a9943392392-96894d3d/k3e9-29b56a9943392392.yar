rule k3e9_29b56a9943392392 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.29b56a9943392392"
    cluster      = "k3e9.29b56a9943392392"
    cluster_size = "6481"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "adload installmonster bundler"
    md5_hashes   = "['000133bc56bf61066ed1b49ed4294e04','000a638b611821a3c8ee903e6c11f4f6','0091b81e07a01488e0b53476b68c5b34']"

  strings:
    $hex_string = { 3b b5 a8 8e 51 4b 6f d4 2d b7 f8 86 59 d7 7f 68 7c e2 b4 42 a3 a4 0a af 74 95 1c 3c 94 08 8a aa 64 9a 0d d5 71 c6 9e 1a a1 16 56 69 a2 6e 22 80 14 92 36 f3 2a d3 4f 0c f2 50 fc 8f 7c 76 ba f5 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}