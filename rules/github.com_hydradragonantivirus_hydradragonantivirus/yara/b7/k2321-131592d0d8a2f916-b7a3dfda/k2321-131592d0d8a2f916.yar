rule k2321_131592d0d8a2f916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.131592d0d8a2f916"
    cluster      = "k2321.131592d0d8a2f916"
    cluster_size = "9"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "regrun ludbaruma rontokbro"
    md5_hashes   = "['0eb016bafdde73e0c1867fc820268c0d','2550b2c5ddb0ecaa0129ad4ac0c01d53','edca1356fa67a90cb2f21a8b73bf885a']"

  strings:
    $hex_string = { 03 84 07 4a 09 36 8a b9 5f 88 78 29 99 9a 42 eb cb a4 75 cd 7c 1c 80 b2 6f 70 24 2e 64 22 12 31 ab 93 f8 5c fc 4c 96 74 27 1b 9b 45 c9 4d 04 be d5 d4 54 ea dc 90 a9 39 22 5d ac 3b 13 65 dd 79 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}