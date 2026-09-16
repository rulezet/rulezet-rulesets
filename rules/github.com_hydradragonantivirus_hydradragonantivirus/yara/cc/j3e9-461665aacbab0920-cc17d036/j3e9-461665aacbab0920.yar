rule j3e9_461665aacbab0920 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.461665aacbab0920"
    cluster      = "j3e9.461665aacbab0920"
    cluster_size = "29"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "bayrob ellell small"
    md5_hashes   = "['07038f1af9fd284f29987ff2de797538','207d304651018b4dc857de121cd68777','cfda1ccb5e6cc4cffad9c6f0d0c2316a']"

  strings:
    $hex_string = { 3b 34 ff 42 41 39 ff 4c 51 43 ff 54 3d 3e ff 32 72 48 ff 00 f3 72 ff 52 e6 af ff 97 e7 e4 ff 72 e5 d5 ff 74 e7 d4 ff 96 e8 de ff 99 e9 e0 ff 9b eb e2 ff 9c ec e6 ff a5 f0 ed ff ab f2 ef ff b2 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}