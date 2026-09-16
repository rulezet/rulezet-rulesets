rule k3e9_1b1c689c87a10b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1b1c689c87a10b16"
    cluster      = "k3e9.1b1c689c87a10b16"
    cluster_size = "2559"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "neshta nestha hllp"
    md5_hashes   = "['000fe19e51a8ae98c606af27fd5a4394','00284777f159458fd704a266764ea9f5','01f52c4fc57849b1cb44684904dc4f1d']"

  strings:
    $hex_string = { 08 18 4e db 82 81 f5 a5 d0 32 aa cb 90 2b 5e fe 90 c7 ba e3 57 97 cb 0b 90 b5 e1 d9 6e ca 12 58 fd b1 15 2e 9a 74 db 4e f3 c4 9e 74 93 ee e2 68 ee 11 84 8b c0 60 88 b2 f2 54 f8 35 fd 9c 91 40 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}