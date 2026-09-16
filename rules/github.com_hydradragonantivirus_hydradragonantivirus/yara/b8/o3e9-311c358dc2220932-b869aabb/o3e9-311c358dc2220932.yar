rule o3e9_311c358dc2220932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.311c358dc2220932"
    cluster      = "o3e9.311c358dc2220932"
    cluster_size = "530"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vbkrypt razy eyestye"
    md5_hashes   = "['0004309e6dd2c46a3f64f630b6648d60','00204b836494f0e0448b0d1dcdf5d53b','1252aa5cc97ef3213cd60052f48d1bf9']"

  strings:
    $hex_string = { 89 53 9c dd 97 bb 8f fd 16 0d e6 4c ba 6f 2d 4b 9a 95 a4 af bc fd 09 20 be 86 ff ff 6b ec fa d6 a9 71 d8 37 54 3f a1 ec 16 92 4f 9c 9b 19 95 b4 30 fe 09 20 1e a1 ff ff e5 cd 86 49 b1 8b c7 5f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}