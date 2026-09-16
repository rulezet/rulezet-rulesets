rule k3e9_1395b6abce200916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1395b6abce200916"
    cluster      = "k3e9.1395b6abce200916"
    cluster_size = "1209"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171119"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ipamor backdoor pyzbaukwkdpb"
    md5_hashes   = "['00844356ea61f3a8959f7a19c15e1645','00848a66685dd8c2d5039e9a7fa8328f','0309bd9c9fb550508db0ff8bd8378f6b']"

  strings:
    $hex_string = { 62 6c 65 2d 66 61 75 6c 74 2e 00 56 49 4e 46 5f 48 4d 5f 44 4f 55 42 4c 45 5f 46 41 55 4c 54 00 49 6e 76 61 6c 69 64 20 6f 70 63 6f 64 65 20 62 79 74 65 28 73 29 2e 00 56 45 52 52 5f 44 49 53 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}