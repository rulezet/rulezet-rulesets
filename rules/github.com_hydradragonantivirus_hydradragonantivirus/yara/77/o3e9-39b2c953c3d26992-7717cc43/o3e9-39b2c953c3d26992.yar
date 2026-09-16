rule o3e9_39b2c953c3d26992 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.39b2c953c3d26992"
    cluster      = "o3e9.39b2c953c3d26992"
    cluster_size = "49"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['06e4862688ff7f22c08ea63c397e32ad','0c8cf135f02142ba2ff5c79d9b561df5','5edd97d4d46bcc28402375db5da274fc']"

  strings:
    $hex_string = { 8d e0 03 fc 90 68 d8 a5 92 62 6e c0 0a 75 07 36 5e 3c f5 35 9b 01 d2 29 b7 6a f9 e6 72 fd 4a 09 b8 da 2b 1a 31 12 24 1c 14 d4 ef bf 54 4b 3a 5f 2d 95 10 30 e4 1e c9 77 2a fe 33 f3 64 8b 97 b5 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}