rule k3e9_2b9554bcd99bd916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2b9554bcd99bd916"
    cluster      = "k3e9.2b9554bcd99bd916"
    cluster_size = "8"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor cossta farfli"
    md5_hashes   = "['10c0a6b15a6d1903541cde3fa7bcf37a','296729b1f3aac178ffe2ec002e484014','f1999c01d6cbddbbad55f3bbc3c792ff']"

  strings:
    $hex_string = { 1a 59 b1 3a 81 4f 13 f2 f1 ce fa 1b 17 df 83 34 35 bd 51 60 68 88 66 20 a3 29 37 02 2c be 7e 4e ce da c1 bb d2 f8 73 f0 04 1f c6 07 bd 32 ca 1c b5 71 42 e9 b9 b3 91 22 9f 10 f5 3c b4 61 d8 a1 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}