rule j3f0_2936969bdee31912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f0.2936969bdee31912"
    cluster      = "j3f0.2936969bdee31912"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "malicious malob crypt"
    md5_hashes   = "['3a92204dccc7c6c88e656c6c605d299c','3d2e67102d0db44212b71f6dae0f4fc5','b3a019f8a88e3ac77b318f59de148719']"

  strings:
    $hex_string = { 61 6c 00 55 53 45 52 27 00 88 0e 77 73 70 72 69 6e 74 66 41 00 57 49 4e 48 54 54 50 c0 5c 25 37 f8 04 4f 70 65 6e 00 60 e8 62 db 58 05 9f 21 55 e8 00 17 8b 30 03 f0 2b c0 8b fe 66 ad c1 e0 0c }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}