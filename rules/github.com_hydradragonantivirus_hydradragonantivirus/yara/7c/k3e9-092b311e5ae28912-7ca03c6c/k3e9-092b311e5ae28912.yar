rule k3e9_092b311e5ae28912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.092b311e5ae28912"
    cluster      = "k3e9.092b311e5ae28912"
    cluster_size = "211"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "jeefo hidrag flood"
    md5_hashes   = "['09169d77eb2768bc2b2d6f69636708b0','0a486eb4ea0f88c3806bc3e0257e7d1b','3a13715b15a7514e97fbdf727df8ebd9']"

  strings:
    $hex_string = { 37 9f 39 a2 3b b0 3d 3e 3f e9 41 62 43 91 45 af 47 ab 49 bc 4b bb 4d c1 4f bf 51 b8 53 c8 55 76 57 9b 59 c9 5b ce 5d ce 5f cf 61 d4 63 c5 65 da 67 d1 69 d9 6b da 6d 9c 6f 90 71 b3 73 e0 75 e2 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}