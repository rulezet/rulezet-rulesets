rule k2321_091b8d9a99e30912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.091b8d9a99e30912"
    cluster      = "k2321.091b8d9a99e30912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['00c835ff4dfbaa0afe54b88de976d1f2','04415b2436399e8e22a2437d22c9fe58','e9deabd3b9db2482d942f57f8f5ab9d8']"

  strings:
    $hex_string = { db 7f 60 0c f2 a6 f8 ca 6f e7 2b bf 5d b8 6a 93 1a 41 07 4d bb cf aa 34 a2 ff 23 42 3c 1d 48 d9 0e a0 ac df 8a ef d4 b6 fa f9 29 b5 c3 16 dc 59 c7 fb 5f 27 36 72 c2 85 97 d0 79 9a fe 37 ba 3f }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}