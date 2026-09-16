rule k3e9_1690d7e1ca000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1690d7e1ca000b32"
    cluster      = "k3e9.1690d7e1ca000b32"
    cluster_size = "1350"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "generickd bublik small"
    md5_hashes   = "['003821db664e5b5154b7c83cffb986f1','0048a722283c1db334693c50e2b0e4e6','0600f4b537e52866c20fa15d0d7fc489']"

  strings:
    $hex_string = { 51 53 e8 21 ca 74 aa 63 79 86 ce c9 c4 00 66 a9 ee a5 e1 b4 21 eb 5a a5 28 4b 69 e3 2a 88 29 00 d3 6f dc 71 68 e7 ee 5c 63 10 6b 1b 25 38 3c 17 fc 6e 95 a0 7f a6 71 2f 20 bd cb e0 76 33 34 54 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}