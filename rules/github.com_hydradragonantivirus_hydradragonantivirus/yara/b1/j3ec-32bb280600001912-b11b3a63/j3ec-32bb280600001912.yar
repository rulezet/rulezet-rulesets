rule j3ec_32bb280600001912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3ec.32bb280600001912"
    cluster      = "j3ec.32bb280600001912"
    cluster_size = "4"
    filetype     = "PE32 executable (console) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cosmicduke backdoor razy"
    md5_hashes   = "['33c8c3c3ae0affb86b630af5bcf53dec','3605f29512b71b1dca0a9872c893b3c4','fe21cbe84790be72669a1eb50d021eff']"

  strings:
    $hex_string = { ae c1 f2 78 da 9b 3c 77 b1 64 4b fc 27 17 fd be 94 ac 8b 3e d3 d2 f6 d1 d1 e1 81 d2 f0 58 c7 5d dd 23 7d 63 e3 03 a3 f1 50 6f 4b d6 0d 8f 8e 97 36 f4 8d ec 1a 2e 25 f7 17 b6 6d 29 6c ea b8 6b }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}