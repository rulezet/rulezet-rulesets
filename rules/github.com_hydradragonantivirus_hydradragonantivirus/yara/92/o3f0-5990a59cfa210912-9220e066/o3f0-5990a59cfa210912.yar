rule o3f0_5990a59cfa210912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f0.5990a59cfa210912"
    cluster      = "o3f0.5990a59cfa210912"
    cluster_size = "9"
    filetype     = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "filetour symmi fnuj"
    md5_hashes   = "['09aa0fbd0f1e155f1465ed9807b1ba2c','1afb72145e8c459acdfe1ac6042ed1cb','fbab3afe3250c1f11f8d5a1ff5bd442b']"

  strings:
    $hex_string = { 6b 07 32 51 84 b0 f6 62 be b7 38 de fb 6e 36 39 8a e4 f2 dd c4 61 6f cd cb 52 a5 29 79 81 bd 97 68 77 c3 f3 01 9c fc f0 9c 54 f9 30 73 fd 4f 8c 8d a7 c2 3c a2 96 99 64 59 10 e1 b5 1f 50 ab 60 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}