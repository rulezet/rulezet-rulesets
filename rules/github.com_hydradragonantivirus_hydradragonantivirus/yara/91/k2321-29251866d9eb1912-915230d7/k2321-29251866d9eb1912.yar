rule k2321_29251866d9eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.29251866d9eb1912"
    cluster      = "k2321.29251866d9eb1912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus barys vbkrypt"
    md5_hashes   = "['75051b3cae1e97746117f690ed1ce22e','89448879c27c06497b5decbe324ffa3c','fb6ff67c91db37d8b98e1dbe138b1038']"

  strings:
    $hex_string = { 2e 57 a2 8f 8e 81 82 59 30 a0 ce 57 d9 9f f8 c9 99 55 d0 05 9b 8d ce 07 5d 85 3c 2b b6 84 47 ad 9c b5 ff 68 5c 27 a5 64 1d 17 3d c7 1a b4 62 e4 22 d1 f1 25 6e 66 fb 6f a6 32 f6 61 ec af 4f 65 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}