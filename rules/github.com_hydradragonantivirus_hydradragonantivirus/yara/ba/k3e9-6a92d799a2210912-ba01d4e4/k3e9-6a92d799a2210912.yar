rule k3e9_6a92d799a2210912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.6a92d799a2210912"
    cluster      = "k3e9.6a92d799a2210912"
    cluster_size = "4173"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "netcat remoteadmin autoit"
    md5_hashes   = "['0002304d6636643e99b6eec5f0225400','000df2eb5276dc8fff219e9c65de18e0','00b7728e61368f854f9a77defa44fda3']"

  strings:
    $hex_string = { 02 7c 77 e3 d4 d1 27 9a 97 9c 2a 0d f9 75 e2 c7 e0 b7 bb f6 47 f1 94 b6 c4 ca e5 2b 50 76 59 99 a9 8a b2 c2 15 13 87 79 61 f2 6b 16 5c db aa b1 a2 f0 d9 09 83 d3 3f 31 b5 cf 53 7f dd 50 fb b3 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}