rule k2321_2114ed699cbb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2114ed699cbb0b12"
    cluster      = "k2321.2114ed699cbb0b12"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "emotet tinba vbkrypt"
    md5_hashes   = "['3ec0f6a82c90a3af94521b07a3850049','b98a1b68e62f29cf95883ee22e83dbe7','eeb52ccc4787b0168a9733377ee61c06']"

  strings:
    $hex_string = { 3b 23 92 9d 1b ce 9a 1c c2 4a 0d 64 27 69 b9 e1 1a b1 5e ab 54 ca 65 02 f2 f6 ba 2f c3 af bd cf f7 99 0c 0e 9b 25 12 0a d4 0a 45 80 46 1d a8 56 e8 95 d2 20 b5 38 5c 2d 8a 52 0b a3 35 82 68 8d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}