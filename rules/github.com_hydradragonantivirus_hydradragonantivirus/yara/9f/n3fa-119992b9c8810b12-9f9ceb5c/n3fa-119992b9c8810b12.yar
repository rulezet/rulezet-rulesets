rule n3fa_119992b9c8810b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3fa.119992b9c8810b12"
    cluster      = "n3fa.119992b9c8810b12"
    cluster_size = "14"
    filetype     = "PE32+ executable (DLL) (GUI) x86-64"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "kryptik fari malicious"
    md5_hashes   = "['04910d8b10e5bed15a2d89fab283d9fd','2020f2b46a6ddb5edbf90ee511b3e8cc','e669c42bfe39ceaa53f86d3902d36aa0']"

  strings:
    $hex_string = { d6 33 12 64 90 23 2d a8 e8 fd 1d 50 d8 aa 1c c9 ec 62 fc 9a a5 7f c4 fb 45 ac a0 d0 19 1b 61 d3 cb 66 a7 0b 2e 2a ce f2 7b 93 8e 99 e3 1e b5 21 e6 2b 01 09 42 0f db cc 58 22 f3 5d 5a 60 34 4f }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}