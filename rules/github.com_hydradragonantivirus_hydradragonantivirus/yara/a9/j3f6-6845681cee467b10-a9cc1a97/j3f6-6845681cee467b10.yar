rule j3f6_6845681cee467b10 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f6.6845681cee467b10"
    cluster      = "j3f6.6845681cee467b10"
    cluster_size = "175"
    filetype     = "data"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171119"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "adload nsis nsismultidropper"
    md5_hashes   = "['05d154ed7229b4cff9e62c0d1045b6b1','075fb2d4d346b4bc13a0fa5d19c00f83','1b56b18e2d1fb512a59e928cda0c2502']"

  strings:
    $hex_string = { 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d 20 76 32 2e 34 36 00 ff 82 80 20 53 65 74 75 70 00 43 61 6e 27 74 20 77 72 69 74 65 3a 20 00 43 6f 75 6c 64 20 6e 6f 74 20 66 69 6e 64 20 73 79 6d 62 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}