rule o3e9_15792c629ed3699a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.15792c629ed3699a"
    cluster      = "o3e9.15792c629ed3699a"
    cluster_size = "961"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['003e92a948e836e490410dcbc7e64736','00873707087ccddba540d66c3834b819','039c92e68e3d756c592dd94108fe3c4d']"

  strings:
    $hex_string = { e8 5a 96 dc a0 00 14 a0 b9 fd 41 56 fe ed fd 7a b5 50 e4 12 1e d9 44 8f 29 39 fd 0a 7c c4 65 c5 70 8a 0e 24 02 77 2a 91 ba 10 59 f1 24 fd 56 cf 8f 64 d5 6a 56 2c 58 7e d3 89 06 03 a7 67 ae 72 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}