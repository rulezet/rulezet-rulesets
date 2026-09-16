rule ofc8_499c1cc9cc000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=ofc8.499c1cc9cc000b12"
    cluster         = "ofc8.499c1cc9cc000b12"
    cluster_size    = "1039"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "smsreg riskware androidos"
    md5_hashes      = "['8294fc0541203667a85ea4c121d1ded33e283211','4f187ad88d0f01a48d4e87323620ec5beb712138','d503f7926998a6f2215c8efea9f7a5fc4c39a940']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=ofc8.499c1cc9cc000b12"

  strings:
    $hex_string = { 2f 68 02 16 75 bd 5e 6a 2e 39 29 f0 9c e4 64 d7 cf 1d ef d0 d2 52 2a ee f9 e2 f7 ad 0a d8 06 1f 72 db e6 3f 8d a2 7d 97 4e f2 90 e5 6e b4 f3 11 70 73 a4 78 67 33 37 93 38 4c 9e 6d c8 96 27 8b }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}