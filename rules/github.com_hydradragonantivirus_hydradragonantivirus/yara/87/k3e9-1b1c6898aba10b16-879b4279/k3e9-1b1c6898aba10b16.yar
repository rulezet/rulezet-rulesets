rule k3e9_1b1c6898aba10b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1b1c6898aba10b16"
    cluster      = "k3e9.1b1c6898aba10b16"
    cluster_size = "7"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "neshta hllp neshuta"
    md5_hashes   = "['4420634200f1d5e8ad2c010bb5594321','493169318dcccd3905bf9e421f522e8a','eb63ce64d7c44c119cc9a75119af5b40']"

  strings:
    $hex_string = { 02 2c 20 8a 57 ff 88 d4 80 ec 61 80 fc 19 77 03 80 ea 20 b4 00 29 d0 75 05 80 fa 00 75 d2 5e 5f c3 8d 40 00 97 92 83 c9 ff 31 c0 39 f8 74 06 f2 ae 48 48 29 c8 89 d7 c3 56 e8 3a fb ff ff 89 d6 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}