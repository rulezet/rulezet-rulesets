rule k2321_291b0ab9ca200b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.291b0ab9ca200b32"
    cluster      = "k2321.291b0ab9ca200b32"
    cluster_size = "8"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nitol servstart cfecc"
    md5_hashes   = "['056dbe0e484f276cc080db04679b37eb','3f31e49a974cda6776f9c7db7b2eb7d3','e3dab9aab670f9e24aa01374c6a516e1']"

  strings:
    $hex_string = { 61 65 64 2d 8d b7 23 5d 7c a5 c5 51 38 e1 d7 74 3a bf 7e 44 d3 69 73 fd d0 b4 7f dd bb ef a3 5d a1 9d d6 57 9b de bd 6e 5f 04 e3 bc f5 55 ca df 95 90 47 19 b9 59 4e b0 30 fe 7b 07 1e ff 57 1d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}