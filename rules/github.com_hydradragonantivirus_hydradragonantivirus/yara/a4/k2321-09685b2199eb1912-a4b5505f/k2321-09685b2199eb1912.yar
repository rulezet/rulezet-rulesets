rule k2321_09685b2199eb1912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.09685b2199eb1912"
    cluster      = "k2321.09685b2199eb1912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vobfus razy autorun"
    md5_hashes   = "['59ec10f53cb86aadb9398830421b1f06','5a1f941b582e97b317d6b40cfc287593','fcb39eb841adbb74e85d42889679f80d']"

  strings:
    $hex_string = { d1 83 a4 82 a5 bd 16 55 8b 60 ab ca db 91 c3 62 b7 71 24 1e 46 42 fc e7 ed 43 88 ff b0 41 7a de 6e fa 72 8a f8 0f b3 c7 3c 33 0c 90 5e d7 68 ce b9 e9 93 b5 ae c9 1c 3d 1b 32 25 50 de 9b 11 03 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}