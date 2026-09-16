rule k3e9_15ba76b1c2200932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.15ba76b1c2200932"
    cluster      = "k3e9.15ba76b1c2200932"
    cluster_size = "11"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "mdeclass dangerousobject dldr"
    md5_hashes   = "['0639bc661952db9b010cd60525437ed4','1ebda270eb4990939a8781889d7be490','f010863a6e4abd8de4b68d47e3d1f2f0']"

  strings:
    $hex_string = { 4f 9d 8c 72 5d 1a 81 a2 eb 55 f3 b0 01 ad 3c 71 ac 32 8f 05 6b 86 9a 27 00 32 97 6a 4d c9 64 14 4b 29 bb c2 d9 29 b9 2e ec 63 b3 e1 cf 3f 0b 56 90 f8 62 1b 7e eb a6 07 e2 de 7f 5e 6d 40 38 d4 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}