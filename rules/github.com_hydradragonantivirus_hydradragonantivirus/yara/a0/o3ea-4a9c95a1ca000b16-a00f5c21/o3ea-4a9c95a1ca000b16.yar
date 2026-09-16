rule o3ea_4a9c95a1ca000b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3ea.4a9c95a1ca000b16"
    cluster      = "o3ea.4a9c95a1ca000b16"
    cluster_size = "1273"
    filetype     = "application/java-archive"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androidos riskware smspay"
    md5_hashes   = "['002dd9fd3a2192b6d3661240e3469c5c','00abf0f5a2ef4da26e8c3dd61fb2be13','026d558c9d38609cc5cf282b09f9f934']"

  strings:
    $hex_string = { df 2c 01 f9 74 d4 7b da dd a2 32 ed ce 6f d8 bb d0 5e db 7d 16 9e 4d 4f 5b 61 51 68 af 3e ee 7e 55 6c 50 1a f7 a7 6a 84 3a ef 46 39 53 f2 ec 97 cb 64 98 3d b9 9b 59 2b 63 0d a1 8f 08 a5 09 ae }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}