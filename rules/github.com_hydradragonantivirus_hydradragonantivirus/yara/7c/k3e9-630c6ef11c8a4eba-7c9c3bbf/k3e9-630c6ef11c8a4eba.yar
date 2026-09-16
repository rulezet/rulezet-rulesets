rule k3e9_630c6ef11c8a4eba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.630c6ef11c8a4eba"
    cluster      = "k3e9.630c6ef11c8a4eba"
    cluster_size = "6"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['3c975d371c7ee0e6e328e037dea267f4','459ab7d0361ad3b343707867623f4498','ebe78d4dc6143764fb726c98819722ce']"

  strings:
    $hex_string = { 86 e0 2c 41 3c 1a 1a c9 80 e1 20 02 c1 04 41 38 e0 74 d2 1a c0 1c ff 0f be c0 5b 5e 5f c9 c3 56 8b 74 24 08 85 f6 75 04 33 c0 5e c3 57 e8 bb d7 ff ff 8b 78 64 3b 3d c4 73 00 01 74 07 e8 e9 e5 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}