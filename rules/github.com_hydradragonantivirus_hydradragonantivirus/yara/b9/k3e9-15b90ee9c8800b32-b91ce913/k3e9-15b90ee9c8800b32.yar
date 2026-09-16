rule k3e9_15b90ee9c8800b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.15b90ee9c8800b32"
    cluster      = "k3e9.15b90ee9c8800b32"
    cluster_size = "531"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "generickd bublik small"
    md5_hashes   = "['01e2e82d433fa53b9bff061b1e1d44bc','02771ffda9fc50fed992b927642a325a','15b5b4e72d461414755721761bf9e18e']"

  strings:
    $hex_string = { 5d 35 b4 59 ed 49 00 25 00 40 68 e8 e6 7d c0 94 ad aa 46 85 b8 9a 25 40 00 68 00 e8 0c 47 a4 ca 05 42 38 32 e8 25 68 00 40 00 4c 62 e3 18 9d 45 c2 39 40 e8 00 00 68 25 33 bd 88 4f d3 81 cc a0 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}