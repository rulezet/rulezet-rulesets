rule j3e9_34645db91db4cb4e {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e9.34645db91db4cb4e"
    cluster      = "j3e9.34645db91db4cb4e"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut malicious attribute"
    md5_hashes   = "['5335b28c6b6655e4e81604d0bb542204','abb9e6bdaf1e0f56ed8af364a4d6c832','bf4bc066bebc51671556feba5c9008ae']"

  strings:
    $hex_string = { 82 b9 40 bf 3c d5 a6 cf ff 49 1f 78 c2 d3 40 6f c6 e0 8c e9 80 c9 47 ba 93 a8 41 bc 85 6b 55 27 39 8d f7 70 e0 7c 42 bc dd 8e de f9 9d fb eb 7e aa 51 43 a1 e6 76 e3 cc f2 29 2f 84 81 26 44 28 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}