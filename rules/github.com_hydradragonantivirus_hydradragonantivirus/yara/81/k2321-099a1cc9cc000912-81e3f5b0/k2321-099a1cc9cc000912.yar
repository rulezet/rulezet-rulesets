rule k2321_099a1cc9cc000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.099a1cc9cc000912"
    cluster      = "k2321.099a1cc9cc000912"
    cluster_size = "14"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "rincux ddos stormattack"
    md5_hashes   = "['05f1c3f928c9ded3bcf1b4e611ad82cb','2ea66ffff0eff17d5a4b67524717a7b4','fd0cdb247f05b1bce3099c07b323b0c3']"

  strings:
    $hex_string = { 80 a5 cd 53 48 5e 21 6f 96 a0 63 06 cc c0 47 43 75 9c bb 7c 5c 52 67 03 d9 3d ec 89 34 49 f6 5b 22 a7 9b 38 e5 87 e1 90 da dc 29 a4 7a 58 5f 2f 3b 84 f3 68 ce c3 1e 07 18 e2 4c fc 78 22 a3 ea }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}