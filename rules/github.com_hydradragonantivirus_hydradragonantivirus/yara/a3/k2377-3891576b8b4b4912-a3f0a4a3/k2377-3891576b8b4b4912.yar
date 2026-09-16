rule k2377_3891576b8b4b4912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2377.3891576b8b4b4912"
    cluster      = "k2377.3891576b8b4b4912"
    cluster_size = "7"
    filetype     = "HTML document"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "script iframe iframeinject"
    md5_hashes   = "['08dc0ce843fa1f0188591adc98a79187','601d33f189a811485695c96a87366493','e083882d86a7d1ed2d883836ca5608a1']"

  strings:
    $hex_string = { 73 6f 62 6f 74 c4 99 20 38 20 67 72 75 64 6e 69 61 20 32 30 31 32 20 72 6f 6b 75 20 70 72 7a 79 20 e2 80 9e 43 48 41 43 49 45 20 4e 41 20 47 52 4f 4e 49 55 e2 80 9d c2 a0 20 6f 64 62 79 c5 82 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}