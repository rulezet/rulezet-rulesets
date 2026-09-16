rule k3e9_2a59a12c8ac2d131 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2a59a12c8ac2d131"
    cluster      = "k3e9.2a59a12c8ac2d131"
    cluster_size = "3470"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dropped malicious zbot"
    md5_hashes   = "['007c4c33b7b4502bc2ace6794c9f31bd','0120c6c21604e3052e2769b812a1ff75','052454616aa685d7204be3eb3bbd87a9']"

  strings:
    $hex_string = { 14 c1 e0 10 23 da 57 8b 7c 24 1c 0b c3 66 89 71 02 89 79 08 89 41 04 83 c1 0c 83 21 00 3b f2 7f 15 85 f6 7e 15 23 c2 0f af c6 57 50 51 e8 3a e7 ff ff 85 c0 75 04 33 c0 eb 03 33 c0 40 5f 5e 5b }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}