rule o2321_19922122d982d115 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o2321.19922122d982d115"
    cluster      = "o2321.19922122d982d115"
    cluster_size = "107"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "optimizerpro speedingupmypc unwanted"
    md5_hashes   = "['006875cd271bc0558acb531e4c5b374f','007c157f881f5646b6a5e50b24b861b3','2763a9a866e3714db235486bdea78b3d']"

  strings:
    $hex_string = { 5d 07 80 a8 7a 1d b5 bd e8 92 34 9a ad e1 0d 91 67 aa 86 a4 0c fb c8 84 ae 17 46 48 c0 dc 4e ce 22 99 0f de c6 0b 58 dd 93 8d 90 33 32 b1 14 e7 69 10 c5 8c 7c 37 fa eb d1 a6 23 7e ed 65 d9 2a }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}