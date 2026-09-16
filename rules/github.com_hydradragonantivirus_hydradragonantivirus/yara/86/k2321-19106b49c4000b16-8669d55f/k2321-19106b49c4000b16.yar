rule k2321_19106b49c4000b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.19106b49c4000b16"
    cluster      = "k2321.19106b49c4000b16"
    cluster_size = "5"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "small generickd upatre"
    md5_hashes   = "['0d1438f7ab120bec39eb3ae1d97177d6','32bc6d52d578db70ca927da56baa549b','955f34c99aed85d69a8c5abcf45cb772']"

  strings:
    $hex_string = { 06 7b 16 57 45 2e df 2c 2a 6d 9a 95 e9 be e7 74 d4 6f 02 58 1f 83 d5 fd f0 f2 a3 c1 27 ba 79 87 17 47 4e b2 9f f5 ca de f5 77 0a d9 78 ea cc 46 db bc 31 93 94 6b 82 7f 2b 9d e3 32 59 80 ed f3 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}