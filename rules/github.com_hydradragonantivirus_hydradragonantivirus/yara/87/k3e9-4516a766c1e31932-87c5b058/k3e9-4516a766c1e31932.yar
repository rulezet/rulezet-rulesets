rule k3e9_4516a766c1e31932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.4516a766c1e31932"
    cluster      = "k3e9.4516a766c1e31932"
    cluster_size = "142"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "servstart nitol daaa"
    md5_hashes   = "['007f10c8630141eef9d21d61d8d32213','00b79af1e3c643575103de68271b1dc3','13b8257e266fde335c493f12b3b223fd']"

  strings:
    $hex_string = { c0 83 fe 01 7e 20 8b d6 57 d1 ea 8b ca f7 d9 8d 34 4e 8b 4c 24 0c 33 ff 66 8b 39 83 c1 02 03 c7 4a 75 f3 5f eb 04 8b 4c 24 08 85 f6 5e 74 06 33 d2 8a 11 03 c2 8b c8 25 ff ff 00 00 c1 e9 10 03 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}