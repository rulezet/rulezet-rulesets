rule i3ed_045e4c492a228b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3ed.045e4c492a228b32"
    cluster      = "i3ed.045e4c492a228b32"
    cluster_size = "50"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "gamarue debris generickdz"
    md5_hashes   = "['0a6000b2ea4997e26c9c24041f29986c','10b59f2278e9e5d82d904f72546342e3','a58da1650c232039bbb133ebde04c56a']"

  strings:
    $hex_string = { 10 40 84 d2 75 f9 2b c1 48 85 c0 7e 13 0f be 0c 37 8a 14 30 88 14 37 47 88 0c 30 48 3b f8 7c ed 5f c3 56 8b f0 e8 cd ff ff ff eb 03 fe 0e 46 80 3e 00 75 f8 5e c3 55 8b ec 83 ec 0c 53 56 57 b8 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}