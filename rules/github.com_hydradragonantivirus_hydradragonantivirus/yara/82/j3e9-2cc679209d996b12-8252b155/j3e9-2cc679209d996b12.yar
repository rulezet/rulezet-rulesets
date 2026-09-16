rule j3e9_2cc679209d996b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.2cc679209d996b12"
    cluster      = "j3e9.2cc679209d996b12"
    cluster_size = "164"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre generickd bublik"
    md5_hashes   = "['0c4a6696c566120594a90fdd4c2edf56','15b50519d0a862267cb609e79c7a39c5','3bfd9507ce9523cabea16d4b3c55b22c']"

  strings:
    $hex_string = { 19 99 26 19 98 26 19 98 26 19 98 26 19 98 21 15 96 38 2e a1 d4 d2 ec 40 3c 9f 2b 22 95 24 17 97 39 30 a2 d4 d2 ec 71 6a bb d4 d2 ec a2 9d d1 27 1a 99 39 2f a2 d4 d2 ec 2b 20 9b 20 14 96 25 18 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}