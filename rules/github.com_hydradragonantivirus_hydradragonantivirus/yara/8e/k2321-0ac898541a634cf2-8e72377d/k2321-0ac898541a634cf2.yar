rule k2321_0ac898541a634cf2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0ac898541a634cf2"
    cluster      = "k2321.0ac898541a634cf2"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy backdoor"
    md5_hashes   = "['084e294f50faede0efa9821e93526b0d','4ce0a43c460201f7ee14082df7fa477f','cd88477c6430942ea738d35adc0f2d26']"

  strings:
    $hex_string = { b6 2b 39 30 a2 a6 ff a8 5c a9 76 ab 14 da 79 48 e6 56 73 03 b8 28 a1 9c 31 46 d0 90 6c 65 af f1 e1 02 25 21 12 ef 10 28 a0 1f f0 d7 04 c5 54 bf aa 8c 27 3a e2 17 b2 fa 3b f9 6e f7 47 f2 bd 2e }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}