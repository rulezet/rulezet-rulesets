rule i3ed_053666e9ee288932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3ed.053666e9ee288932"
    cluster      = "i3ed.053666e9ee288932"
    cluster_size = "72"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "gamarue symmi debris"
    md5_hashes   = "['00560548dbfabb88fe7e4c39c580d513','08d0d8318573e977a005e673db6b5c69','58a023c8cf26a31076e6e1f1cbc74089']"

  strings:
    $hex_string = { 8d 71 fc 3b f0 72 12 8b 0e 85 c9 74 07 ff d1 a1 50 30 00 10 83 ee 04 eb ea 50 ff 15 14 20 00 10 83 25 50 30 00 10 00 59 5e 6a 01 58 c2 0c 00 55 8b ec 53 8b 5d 08 56 8b 75 0c 57 8b 7d 10 85 f6 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}