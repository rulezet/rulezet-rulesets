rule j3f4_490f283dc0800b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f4.490f283dc0800b32"
    cluster      = "j3f4.490f283dc0800b32"
    cluster_size = "8"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "razy agbf asvcs"
    md5_hashes   = "['263727191ce20a08dd9d439031314c9c','2e50c18213e16ea2ee211b4ab922f0a3','f02369aabb481dfd8821508a672f5d9e']"

  strings:
    $hex_string = { c6 ea ff 48 c6 ea ff 47 c5 ea ff 47 c4 e9 ff 47 c4 e9 ff 46 c3 e8 ff 46 c2 e8 ff 46 c2 e7 ff 46 c1 e7 ff 45 c1 e6 ff 46 c1 e7 ff 45 c1 e6 ef 00 00 00 00 00 00 00 00 00 00 00 00 49 c8 eb ff 8f }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}