rule p2321_139896c9cc000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p2321.139896c9cc000b12"
    cluster      = "p2321.139896c9cc000b12"
    cluster_size = "12"
    filetype     = "PE32 executable (GUI) Intel 80386 (stripped to external PDB)"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['056e6b76feeef0c2d960863b11088b89','3397ee5f0312e30fb1d85aa6d7c569e0','f992f7c390928af52057306b3a127aad']"

  strings:
    $hex_string = { 09 fa 05 4d 22 71 d1 b1 18 9b 77 f6 25 90 79 c8 63 1a c4 3e f0 aa 69 01 dd c6 16 d0 5f df 0c c1 b7 fe 37 88 f1 da 68 52 08 0a ff a0 44 e4 97 42 e9 65 57 fb 48 9c 03 1b 47 d8 4b 7e ef f7 31 93 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}