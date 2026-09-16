rule k3e9_1b1c6898b1a10b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1b1c6898b1a10b16"
    cluster      = "k3e9.1b1c6898b1a10b16"
    cluster_size = "522"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "neshta hllp neshuta"
    md5_hashes   = "['0097de110a5fa104749044d38cd8e8c0','009c656b32664d060ff803265833442b','0c09e8641af194759c664e45302049be']"

  strings:
    $hex_string = { 4b 5d 17 2f d4 e4 d1 88 e2 71 cb b6 cf 11 71 38 d5 7a f4 f1 ce 82 11 34 30 a7 37 b3 df 0f e2 7d e8 8b 37 1a 18 8c 1b 63 12 14 70 bc 6e 0b 2b b8 db 8f 55 61 67 25 4e 96 63 c7 c9 4f 8b 62 68 ad }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}