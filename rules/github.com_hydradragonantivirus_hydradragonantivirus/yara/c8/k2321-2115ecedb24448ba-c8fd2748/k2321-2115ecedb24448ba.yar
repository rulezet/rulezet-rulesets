rule k2321_2115ecedb24448ba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2115ecedb24448ba"
    cluster      = "k2321.2115ecedb24448ba"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba crypt emotet"
    md5_hashes   = "['35e9785fa9fd5017272d58d339522449','63cca38ba12777c3e1842d512e905b68','c7099a8551c38d4c40d58e2b47d2dc74']"

  strings:
    $hex_string = { 3f 37 26 b8 76 e8 74 bd 0d 55 4b 29 ca cd 1f 57 34 73 c8 50 ee 3e 84 4f dc 95 65 41 45 fd 36 de 3c 72 a0 ea 8b 77 8d 9f 6c 2b 7f ad 8a 98 2a 5c ab c2 bc ba 55 e0 12 f2 da 8c f8 7e 40 d3 c9 46 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}