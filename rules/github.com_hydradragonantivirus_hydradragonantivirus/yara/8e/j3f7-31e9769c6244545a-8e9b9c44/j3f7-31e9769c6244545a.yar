rule j3f7_31e9769c6244545a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f7.31e9769c6244545a"
    cluster      = "j3f7.31e9769c6244545a"
    cluster_size = "3"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "redirector html script"
    md5_hashes   = "['04358f2fdaabaea790c783d9f7475492','05c28b7715c1fa28cd88b686f92474a3','1481a4add89c80210ca2a35ea752fa17']"

  strings:
    $hex_string = { d1 e7 be c6 b5 ea d3 c5 bb dd d4 a4 b6 a9 b7 fe ce f1 a1 a3 22 20 2f 3e 0d 0a 3c 73 74 79 6c 65 20 74 79 70 65 3d 22 74 65 78 74 2f 63 73 73 22 3e 0d 0a 62 6f 64 79 20 7b 6d 61 72 67 69 6e 3a }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}