rule k2321_09b2b532983b4912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.09b2b532983b4912"
    cluster      = "k2321.09b2b532983b4912"
    cluster_size = "42"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nimnul vjadtre small"
    md5_hashes   = "['013901aca7bce7b1ae29b454b021d602','0f258c8ad17b24baf1f8030b6a6c995f','779bfb9302de432f5a1137200eb8f332']"

  strings:
    $hex_string = { ee 0d 18 95 09 7d 9e dc 60 a6 32 3d e8 d8 0c 7d 90 15 81 40 76 fe f6 19 c6 0a 02 b0 a4 39 36 90 30 a5 89 cb 1d ba 20 7c 94 21 0f 0e a2 ae c2 88 8e e1 74 16 55 86 67 a8 a0 ea 48 a3 d4 1b d0 42 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}