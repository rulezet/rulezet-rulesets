rule k3e9_69d09ce919eb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.69d09ce919eb0b12"
    cluster      = "k3e9.69d09ce919eb0b12"
    cluster_size = "419"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "mywebsearch mindspark webtoolbar"
    md5_hashes   = "['001c7a6da5fe99238b5abc1bc1906af7','004d4c3d48311429b05d6247a50d5709','114e0bc53203af11a563adf992903733']"

  strings:
    $hex_string = { b6 22 bc 6e be ef 95 a4 1d d0 a9 57 bd 7a d4 b8 ee fc f1 fd 0c b9 19 ea 1b d6 f7 5d 3d f8 6a 7f bb 59 e5 aa 53 c6 5a 0f 94 91 72 f0 97 7d 61 60 da 8c f4 f6 2c 74 de a1 34 6c 84 99 e9 80 b3 45 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}