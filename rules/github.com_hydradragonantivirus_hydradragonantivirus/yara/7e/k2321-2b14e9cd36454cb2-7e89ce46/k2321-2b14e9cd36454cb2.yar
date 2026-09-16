rule k2321_2b14e9cd36454cb2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2b14e9cd36454cb2"
    cluster      = "k2321.2b14e9cd36454cb2"
    cluster_size = "10"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba crypt emotet"
    md5_hashes   = "['05ce0e41277cc58ec31ef273f2b7ce38','4387a83490ae922228e5c937596fd20b','ff5b43a6d8d5c22f7d3ce358e4e49ae9']"

  strings:
    $hex_string = { ab ae 6a f0 42 32 90 64 3f e2 98 5c d2 8b a4 1f 73 2c 2f 29 24 e9 27 48 3b 6b 25 19 8c 64 26 f5 91 2b 75 c8 1b 54 b1 6c 92 7e 8a b4 89 16 c3 a8 ce 02 96 4c 72 2a 7b 11 e5 44 37 46 b2 9d 88 2d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}