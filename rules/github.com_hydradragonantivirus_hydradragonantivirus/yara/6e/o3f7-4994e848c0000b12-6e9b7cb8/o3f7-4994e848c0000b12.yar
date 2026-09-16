rule o3f7_4994e848c0000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f7.4994e848c0000b12"
    cluster      = "o3f7.4994e848c0000b12"
    cluster_size = "35"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "script faceliker clicker"
    md5_hashes   = "['009f6c4dc1b3aa412b2d967d5de998cc','0d775c2865cec016bbf841e4d62d30f2','7bbbda89e31a40539ecef6ffaf5f440c']"

  strings:
    $hex_string = { 73 25 43 34 25 42 31 27 3e 59 65 74 65 6e 65 6b 20 53 69 7a 73 69 6e 69 7a 20 54 c3 bc 72 6b 69 79 65 20 32 30 31 31 20 48 c3 bc 6c 79 61 20 41 76 c5 9f 61 72 26 23 33 39 3b c4 b1 6e 20 4b 75 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}