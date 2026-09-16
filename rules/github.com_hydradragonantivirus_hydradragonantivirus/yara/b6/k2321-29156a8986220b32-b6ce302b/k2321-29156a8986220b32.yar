rule k2321_29156a8986220b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.29156a8986220b32"
    cluster      = "k2321.29156a8986220b32"
    cluster_size = "38"
    filetype     = "PE32 executable (console) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "brontok email pazetus"
    md5_hashes   = "['046b79cd8a61d514c41410ee84b04a0a','10324986212470ffa0d89d563e4fd39c','a3ed587cd976a1848ffdf3a6a954c124']"

  strings:
    $hex_string = { 16 95 35 da 30 e8 7c 45 24 e7 40 8e 55 00 34 25 b2 44 51 ca 04 27 ff 46 72 c3 5b fb aa 3f b1 97 49 b0 ea f3 bc 3d 77 f4 7e 0a f8 f6 6a ef 4f bb eb 32 0d 31 1d 1d 1a 3a 5a 4f 4d 36 64 94 0e b6 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}