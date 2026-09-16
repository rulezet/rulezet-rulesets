rule n3f7_499c16c9c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f7.499c16c9c8000b12"
    cluster      = "n3f7.499c16c9c8000b12"
    cluster_size = "17"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit html script"
    md5_hashes   = "['16d904b58c3af3cc4ca5edc1e0e66437','1a74f09d905ba719143764550cfb6afd','f3de7573a394e33209b26c426b52589b']"

  strings:
    $hex_string = "ng.FileSystemObject\")\nDropPath = FSO.GetSpecialFolder(2) & \"\\\" &"

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}