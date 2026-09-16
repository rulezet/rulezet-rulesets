rule n3ed_1929221485224ad2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3ed.1929221485224ad2"
    cluster      = "n3ed.1929221485224ad2"
    cluster_size = "14"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy delf malicious"
    md5_hashes   = "['0a3d2aa392d6e773e9d0e1ea74f39bf9','a0a7b38f601fc0e6bd9ce0d229d79d2f','fc793e7a771cc03d76ed6de7c5d2ce84']"

  strings:
    $hex_string = { bd a2 20 e0 77 4c 8b eb 06 39 78 72 65 9c c2 7f f2 15 ea 75 8f 17 cd 5b e3 ef 89 6c df a8 ff 1b 13 d7 62 42 e5 83 98 d9 0f 32 48 45 0e 1d 76 8e bc 84 b7 57 d4 49 f5 90 9f 7e 64 3e f6 a7 44 92 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}