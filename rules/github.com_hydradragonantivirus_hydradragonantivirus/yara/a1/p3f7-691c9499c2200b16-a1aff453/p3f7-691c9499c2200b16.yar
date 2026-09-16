rule p3f7_691c9499c2200b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3f7.691c9499c2200b16"
    cluster      = "p3f7.691c9499c2200b16"
    cluster_size = "4"
    filetype     = "ASCII text"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androidos shedun triada"
    md5_hashes   = "['0be4366982008d5fc27249bd8da17d6a','0ca9d9920cc28a2bf9de2e6b20d63079','3afdb7fae7910daebe23424c7c1d855b']"

  strings:
    $hex_string = { 10 99 c1 b5 a4 50 b8 51 6e 38 be 84 ef fb 83 5d d1 f9 4f 75 3f cc a3 70 7f 08 7b 19 ec 98 4e 90 4b 96 b0 f7 93 af 97 30 d9 85 dc 59 1b 2d ea c5 24 31 43 0e 76 92 5b b2 0b f2 36 a6 77 ab 23 7e }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}