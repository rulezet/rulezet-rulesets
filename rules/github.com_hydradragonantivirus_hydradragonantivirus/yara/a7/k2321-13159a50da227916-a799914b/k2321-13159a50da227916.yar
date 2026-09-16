rule k2321_13159a50da227916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.13159a50da227916"
    cluster      = "k2321.13159a50da227916"
    cluster_size = "6"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "regrun ludbaruma rontokbro"
    md5_hashes   = "['0f0f2f2c5422f6680470881cc5639997','8f300a0e57531c6e67eec699eb187ce9','ff5ca0565d00a3627e2dffb32c4e90de']"

  strings:
    $hex_string = { 5c 71 ec f6 89 4d 4a 25 ee e9 bb 12 8f 57 2a 3d 10 89 83 49 c5 31 3e 7c b7 92 95 a1 be 04 06 af 1b 58 15 87 37 40 43 9d 47 f7 5b 5e a3 fe c2 3f 63 2b 59 eb da ea 66 bf 1e ae 56 0e 17 dd 4e 38 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}