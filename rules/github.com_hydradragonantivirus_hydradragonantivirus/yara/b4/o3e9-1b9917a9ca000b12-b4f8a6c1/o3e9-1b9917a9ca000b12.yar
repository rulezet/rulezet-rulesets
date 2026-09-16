rule o3e9_1b9917a9ca000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.1b9917a9ca000b12"
    cluster      = "o3e9.1b9917a9ca000b12"
    cluster_size = "9"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installcore dealply unwanted"
    md5_hashes   = "['3615e2da42307bfe59bec827c6b973e4','3f058ec1fba432da9aed3bde3737c3a3','e65175c9cabfde33539552ba19d21f2b']"

  strings:
    $hex_string = { ef 3e 45 be 7a 21 ba 72 35 b1 46 84 a8 aa ed 7c c4 53 77 c5 fd ff 63 6f 06 b8 4b d6 58 94 99 b0 76 3b d8 23 2a d3 dc e9 5f 57 83 9d c8 a2 8c ea 85 01 ce ab b6 9c 5b 3a e8 98 37 c1 92 50 b3 28 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}