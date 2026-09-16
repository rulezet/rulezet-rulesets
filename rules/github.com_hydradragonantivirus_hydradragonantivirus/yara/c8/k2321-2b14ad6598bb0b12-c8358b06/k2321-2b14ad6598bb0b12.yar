rule k2321_2b14ad6598bb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2b14ad6598bb0b12"
    cluster      = "k2321.2b14ad6598bb0b12"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba emotet vbkrypt"
    md5_hashes   = "['0f34a93241789173e6e4b98f69604dbe','3d0caacec4962ea729742fd9108a4819','f4ef3a13cf526f0b20c21c9a3c497f4b']"

  strings:
    $hex_string = { 30 f7 6e dd b8 79 ed 6a bd a9 e6 f3 3d 7b 4a 8a 8b 07 a4 a6 22 e6 09 58 2c 1e 23 00 12 80 04 06 74 56 08 85 62 2e 57 ca e7 83 2b b1 a4 be e9 3e 38 2d 6d e4 f0 e1 63 46 8f fa 73 3c 02 fc fd d8 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}