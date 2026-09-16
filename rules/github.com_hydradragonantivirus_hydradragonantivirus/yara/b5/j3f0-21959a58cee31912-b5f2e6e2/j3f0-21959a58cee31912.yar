rule j3f0_21959a58cee31912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f0.21959a58cee31912"
    cluster      = "j3f0.21959a58cee31912"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "malicious malob atwpt"
    md5_hashes   = "['2548d0e3a8d6bcc71de21afff9e9b26c','2fbfd4a4e1a052da8fa3ee0b9714afe9','b7a6db3c3ae9e4e68a0312fec3e1ac91']"

  strings:
    $hex_string = { 72 1d 8b 39 89 38 2b f2 03 c2 03 ca 3b f2 73 f2 85 f6 74 14 8a 11 88 10 40 41 4e 75 f7 eb 09 8a 11 88 10 40 41 4e 75 f7 0f b6 31 41 83 fe 10 73 57 0f b6 11 c1 ea 02 c1 e6 06 8d b4 32 01 07 00 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}