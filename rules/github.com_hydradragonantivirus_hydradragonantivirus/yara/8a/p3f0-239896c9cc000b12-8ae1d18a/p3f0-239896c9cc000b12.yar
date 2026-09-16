rule p3f0_239896c9cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3f0.239896c9cc000b12"
    cluster      = "p3f0.239896c9cc000b12"
    cluster_size = "10"
    filetype     = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "symmi mediamagnet gamemodding"
    md5_hashes   = "['1706d9fc6c5bbd148513c0692cd56511','23ebd897ff984185cf98bf7797918625','dad28b0297db028acf5979dbf722ba5b']"

  strings:
    $hex_string = { 2b 06 bb 85 86 df 81 77 fd 0b 0d a6 f7 c5 4e 76 5d 92 43 7a 40 9d 14 e4 f2 58 f6 e1 ca a3 d6 89 27 73 fa 22 a7 b3 5b c8 66 78 38 c3 b5 99 15 dc a4 d3 51 b2 6a fb 2c 15 05 01 3b db 16 09 bf 64 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}