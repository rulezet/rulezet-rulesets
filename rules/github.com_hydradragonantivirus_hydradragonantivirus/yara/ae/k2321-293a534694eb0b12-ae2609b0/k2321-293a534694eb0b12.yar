rule k2321_293a534694eb0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.293a534694eb0b12"
    cluster      = "k2321.293a534694eb0b12"
    cluster_size = "9"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre kryptik doxv"
    md5_hashes   = "['5a8f602b82fbc820012745270d073e28','5d6f4890d1463f99c7b82c11b2f56473','e58d02a81ebf869657275b671b712c23']"

  strings:
    $hex_string = { 34 53 ae 0c 3d 78 05 57 ba 81 2b 04 22 be 02 c4 16 95 a8 6b e8 d6 1f 28 a4 bb 84 56 6e c7 c0 12 d9 9c 4e 57 2a 30 a7 d1 d2 0d fc c1 4d af 40 db 09 35 e0 33 1c e4 c8 62 1b 60 dd f5 5d 4c 67 32 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}