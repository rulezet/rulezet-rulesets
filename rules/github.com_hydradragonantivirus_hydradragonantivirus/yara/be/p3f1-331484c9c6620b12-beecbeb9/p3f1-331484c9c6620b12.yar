rule p3f1_331484c9c6620b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3f1.331484c9c6620b12"
    cluster      = "p3f1.331484c9c6620b12"
    cluster_size = "13"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "riskware androidos generickd"
    md5_hashes   = "['00b00fba0fc9f87a454e585af5147ee9','338e4520c7bcc0aa8da764dcb4e84cce','fb3a4687572b4cf65bab7776a9b3ea47']"

  strings:
    $hex_string = { e8 bc e1 0a 9b 05 f7 90 a1 39 53 38 51 e7 35 29 bf bb 28 2f d1 11 87 99 22 b6 f3 7c ca ba 3b e4 43 70 2a 6b 79 41 94 18 b3 d6 25 8b d9 9d be 85 8a ec 42 4d 76 61 46 96 5d 4b 50 55 91 2e 34 98 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}