rule k3e9_29915919d39b1096 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.29915919d39b1096"
    cluster      = "k3e9.29915919d39b1096"
    cluster_size = "38523"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "adload nsis trojandownloader"
    md5_hashes   = "['0000e06c0150f81028ecfc1a66cba615','0000e0feef3ef02db8d8fa6927fff083','002070b904e05657f9968b7fd95cf979']"

  strings:
    $hex_string = { 55 94 7d 29 83 65 98 00 eb c3 ff 45 98 8b 45 98 3b 45 a4 7c b8 6a fc 58 6a 18 59 8d bb 64 e8 37 00 8d 75 94 f3 a5 5f 5e 5b c9 c2 04 00 33 f6 32 c9 39 75 a4 7e 10 33 c0 88 4c 05 f4 fe c1 0f b6 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}