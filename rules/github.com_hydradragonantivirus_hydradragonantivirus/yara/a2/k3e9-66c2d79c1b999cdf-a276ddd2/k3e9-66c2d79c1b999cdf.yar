rule k3e9_66c2d79c1b999cdf {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.66c2d79c1b999cdf"
    cluster      = "k3e9.66c2d79c1b999cdf"
    cluster_size = "129"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "adload nsis riskware"
    md5_hashes   = "['00baf865707b01b6155a1e30695ce3b7','07f22a860bf63a05835a2b733b48b400','28dcfd02e0694b1632ceb0e2f949a992']"

  strings:
    $hex_string = { 4c 24 18 c1 e0 05 8d b4 08 18 08 00 00 8b 46 14 85 c0 74 2a 6a 1a 59 3b c1 74 23 83 f8 ff 75 07 e8 df f0 ff ff eb 22 85 c0 7e 0e 83 f8 19 7f 09 48 50 e8 51 f1 ff ff eb 0f 89 4e 14 eb 0b 68 34 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}