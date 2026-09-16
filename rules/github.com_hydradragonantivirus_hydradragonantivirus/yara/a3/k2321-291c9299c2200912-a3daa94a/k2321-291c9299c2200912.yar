rule k2321_291c9299c2200912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.291c9299c2200912"
    cluster      = "k2321.291c9299c2200912"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['2cfb68d4579ebb30ee665c541d997356','5d31329a3884b129f124b7176e633a00','f2eb6cdcd15bd2bea4b360f7714bd5b9']"

  strings:
    $hex_string = { 16 aa df f7 30 4d 7e b5 cf cc 72 69 8b 09 2d 97 99 1d 52 95 66 de 1e 0b c4 9a fa ac e3 4f 98 b8 bc fc 90 c2 a8 65 25 cb 0e 35 e8 07 a9 9d 4b 6e a2 6d 7c 47 d0 13 38 3a 75 41 a4 ea f3 f9 a5 8d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}