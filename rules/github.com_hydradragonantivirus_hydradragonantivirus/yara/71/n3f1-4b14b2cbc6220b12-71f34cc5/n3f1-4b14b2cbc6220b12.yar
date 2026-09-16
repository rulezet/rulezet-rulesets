rule n3f1_4b14b2cbc6220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.4b14b2cbc6220b12"
    cluster      = "n3f1.4b14b2cbc6220b12"
    cluster_size = "15"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "hiddenads androidos andr"
    md5_hashes   = "['2f8fb461bce617e720ba59f210acfe63','3b372f908a3f46313e2400dacbd2debe','ea6fe2a1338680862c2f1bef6813adee']"

  strings:
    $hex_string = { bd 4c 2b 66 3a c3 a3 b3 04 0b 0c a4 a7 e4 50 d6 5a e0 b6 d3 74 34 95 c7 98 b7 83 e6 4d 24 d2 7e a0 40 28 f8 bb 70 e2 96 2d f0 d7 e5 cd fb 80 56 33 30 9c af 5c a1 3f ab 03 73 89 ec 48 25 91 3c }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}