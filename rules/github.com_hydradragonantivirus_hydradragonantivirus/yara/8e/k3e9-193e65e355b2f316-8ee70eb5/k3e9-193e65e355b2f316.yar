rule k3e9_193e65e355b2f316 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.193e65e355b2f316"
    cluster      = "k3e9.193e65e355b2f316"
    cluster_size = "1760"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installcore dealply unwanted"
    md5_hashes   = "['00381cefa0b1c4dd50ad176238044fd6','005e2a39a00553ef4da97fd0e35ddd4d','0169bb8cdcef5f13a68401cc4d9282e6']"

  strings:
    $hex_string = { 50 77 a4 a0 ce 51 03 55 ff 0e d7 68 a6 17 55 6e 29 c4 b4 ce ea a1 76 a9 4f 00 1d 13 32 7f ef f9 8e ae 8c 39 bf 2b ef 69 59 59 1b 11 13 9e 23 c6 9b c7 19 21 bc 22 e8 0c df 72 f1 4b 99 73 e4 d5 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}