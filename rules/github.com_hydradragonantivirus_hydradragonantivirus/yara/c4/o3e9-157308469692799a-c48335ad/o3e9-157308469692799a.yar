rule o3e9_157308469692799a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.157308469692799a"
    cluster      = "o3e9.157308469692799a"
    cluster_size = "2217"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['000590510cf1d6efd7119a9ac8c3b895','000fe8f959c8ff71efb27f8e5ad2b0a5','01f76e9a67c4a6875c78756f125d227d']"

  strings:
    $hex_string = { 83 1e 46 67 35 84 53 28 2d 1e 67 e1 93 6b 10 cd b1 6d 91 71 98 ab 4f 35 b3 e3 f9 29 a9 5c 64 7d 0a 7a 3e d1 dd 3c 54 a9 f2 2b d2 c8 f4 b8 c1 34 e5 79 82 58 68 1d de b1 fd 02 86 0f 1f ea cc 19 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}