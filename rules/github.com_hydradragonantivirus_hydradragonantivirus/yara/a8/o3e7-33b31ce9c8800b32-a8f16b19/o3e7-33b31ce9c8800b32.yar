rule o3e7_33b31ce9c8800b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e7.33b31ce9c8800b32"
    cluster      = "o3e7.33b31ce9c8800b32"
    cluster_size = "3"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonstr malicious banker"
    md5_hashes   = "['35dd4028bb57b17ae5e0f00cf203b967','6baff55bd950b06f3784a30b39341d92','7b994a0133a3ddba2910a5c59c755880']"

  strings:
    $hex_string = { d5 a6 cf ff 49 1f 78 c2 d3 40 a3 14 9b c5 16 ab b3 ef 3d 41 e0 8c e9 80 c9 47 ba 93 a8 41 aa 17 e6 7f 2b a1 16 b6 12 42 6b 55 27 39 8d f7 70 e0 7c 42 30 c9 3c e3 ff 96 52 8a e7 42 8e de f9 9d }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}