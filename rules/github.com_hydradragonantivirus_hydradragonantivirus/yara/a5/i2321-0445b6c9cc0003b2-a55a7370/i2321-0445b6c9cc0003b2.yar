rule i2321_0445b6c9cc0003b2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.0445b6c9cc0003b2"
    cluster      = "i2321.0445b6c9cc0003b2"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmicduke backdoor razy"
    md5_hashes   = "['1f53cbb949c4ccb130bab816179cdb0a','5512226f207e178bae67105afc8bf1ea','c0582ac3d20ca30f08ecea05c2d90236']"

  strings:
    $hex_string = { 8b 85 10 7e b6 e3 a9 ca fc f3 c5 ca b1 4a 65 7e 26 3c bd b3 b2 58 af 55 4a d5 58 f2 46 ab e4 44 ad 54 0a e1 1b 6d 4f 95 ea c7 e7 2f 5c 28 56 67 47 e7 aa a5 42 38 39 3c fe f4 f0 e8 a1 27 b2 8e }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}