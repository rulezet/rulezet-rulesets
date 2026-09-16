rule k2321_1b1056c9cc000b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.1b1056c9cc000b16"
    cluster      = "k2321.1b1056c9cc000b16"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "small generickd upatre"
    md5_hashes   = "['704fc75296a8c3dd1850160b5bbf9341','7d9c66695b4cf3f1df76f2688b22d329','f4bb8440b5ba7cc4c70857e6b1214085']"

  strings:
    $hex_string = { 75 fc cc ad 26 f3 8a fb 44 b3 17 2e 1d 55 7b c7 9c 11 32 01 4f dd 34 2f be 65 b5 cb b4 2a fb 56 6e d7 39 5e 7f 9b cd d4 99 ed ea 1f 30 25 67 7c 88 5a 40 d6 7e 9f d9 31 e7 4c 80 00 ab 85 37 07 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}