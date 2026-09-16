rule o26c0_5132480a9deb1912 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.5132480a9deb1912"
    cluster         = "o26c0.5132480a9deb1912"
    cluster_size    = "29"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "graftor kryptik malicious"
    md5_hashes      = "['ec9eb9ef5fddb69fab7ab2f9452cf5cd29d73af8','ed1d3e938755819012cea0bcaa9af0462c3a5b2f','b11a7d49a21360654925d1900cb462293f03cd97']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.5132480a9deb1912"

  strings:
    $hex_string = { 1c 5e 3e 3f 17 a7 d7 65 71 ce 48 28 40 d0 9d 92 61 fd 2b 50 55 af 79 e7 21 3b be ee fb e1 ba 1e 7e 4a f4 d2 15 bc 9c de c5 80 a8 9b 77 e6 dd 6a 39 10 f2 f8 8c 90 2e 18 49 81 7b 0f 00 52 3a b4 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}