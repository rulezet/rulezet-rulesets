rule k3e7_35b4b51cc2211912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e7.35b4b51cc2211912"
    cluster      = "k3e7.35b4b51cc2211912"
    cluster_size = "6"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dinwod trojandropper malicious"
    md5_hashes   = "['1347bd0d177a42ba70b73a31cd1fce98','ab6e026d7a90e7b17428240c3cb607d4','ab6e026d7a90e7b17428240c3cb607d4']"

  strings:
    $hex_string = { e4 19 6b 43 47 20 e7 80 8d d2 1a 1b 44 fd 0e 9b 17 c7 da 42 58 13 f7 61 9e 04 76 38 a2 95 ea 62 6c 6f 1e 6a 01 e3 fe 2d df f0 c4 22 e8 85 7d d3 a5 08 7e e8 02 00 3f f4 db 1d fb 9c 10 2a 3e 39 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}