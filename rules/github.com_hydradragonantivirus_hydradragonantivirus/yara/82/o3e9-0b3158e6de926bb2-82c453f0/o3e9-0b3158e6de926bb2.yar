rule o3e9_0b3158e6de926bb2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.0b3158e6de926bb2"
    cluster      = "o3e9.0b3158e6de926bb2"
    cluster_size = "13"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster malicious browsefox"
    md5_hashes   = "['18525f4b03bc544f9e9459a6a91ee871','1bae8502944ff6dcd1db93175b5f8074','f1d8a381b2b7593336be66c0dfaa9b3d']"

  strings:
    $hex_string = { 3a 57 b4 4b 27 df 6f 12 25 d5 d9 77 bd c2 b0 81 e9 8b 42 82 2c b6 65 9e 00 dd 4e 51 c5 4a fd be 0f 6d 9c ad 86 a5 93 ab a3 63 58 08 e3 fc 8d e8 9a 22 a7 87 53 a9 7e c0 9d 49 84 44 d3 3c 20 02 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}