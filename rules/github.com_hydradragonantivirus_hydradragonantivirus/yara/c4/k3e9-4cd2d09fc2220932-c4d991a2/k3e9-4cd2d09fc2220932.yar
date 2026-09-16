rule k3e9_4cd2d09fc2220932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.4cd2d09fc2220932"
    cluster      = "k3e9.4cd2d09fc2220932"
    cluster_size = "2203"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre ipatre kryptik"
    md5_hashes   = "['002b817879a7f416c833eadafb36bccf','002ce59951efa19e95284f3ddb0f3b26','01bf76855e1156db2daa8df7793560bc']"

  strings:
    $hex_string = { d4 43 06 52 b2 23 1f fe 61 0a a9 73 8d b1 ca 56 35 32 f4 4a ab 73 a9 cb 5f 26 b6 fd cb 7e 86 bd 44 f8 8f e2 42 09 64 f5 77 2e 82 51 c6 22 bd 4c fc e9 2a 67 fe 61 12 a1 53 c9 34 87 57 a6 b9 94 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}