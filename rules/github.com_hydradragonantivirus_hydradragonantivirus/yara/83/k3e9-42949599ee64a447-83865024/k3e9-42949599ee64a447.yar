rule k3e9_42949599ee64a447 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.42949599ee64a447"
    cluster      = "k3e9.42949599ee64a447"
    cluster_size = "23"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['947853df4dd7e11fd4b5d581d18586dd','a2ee1bf0055ddcfa8912a865778bf6c7','df67ec3fd0b876791f3597d9e75f78c1']"

  strings:
    $hex_string = { 2c 0c 4f 9d a2 17 43 11 ac c3 27 8c e9 31 8c 3a 98 a5 48 90 16 6f e5 d6 67 a9 50 26 91 28 ce 84 9e a7 45 93 7e 67 bb 18 69 14 93 ab df f7 88 a7 3e 3a 4c ae fb c4 e8 10 61 73 aa 68 e6 82 51 5e }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}