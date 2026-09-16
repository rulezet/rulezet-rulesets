rule i2321_13b24517ca230b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i2321.13b24517ca230b12"
    cluster      = "i2321.13b24517ca230b12"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "padodor backdoor symmi"
    md5_hashes   = "['6065bb6bf03337a6ceaefdfb885bf701','98227e9655238de475acb2e876e6d623','e1db2e9b12c77f1ebb700dd61dcac4d8']"

  strings:
    $hex_string = { ea 70 19 16 0e f1 98 0e fb f9 74 17 ae b0 b8 19 47 89 7d ed f6 0a 49 b6 2f 6e 92 63 bc bd 28 aa 52 0a 48 57 3a a8 5e 7f 6f 28 fd b7 3e 87 e3 e0 a2 1c 4a 38 df f7 a1 36 35 f4 4f 75 f8 08 18 12 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}