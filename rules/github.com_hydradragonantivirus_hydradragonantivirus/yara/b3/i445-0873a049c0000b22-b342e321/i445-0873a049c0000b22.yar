rule i445_0873a049c0000b22 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i445.0873a049c0000b22"
    cluster      = "i445.0873a049c0000b22"
    cluster_size = "4"
    filetype     = "MS Windows shortcut"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "vbsworm winlnk jenxcus"
    md5_hashes   = "['8375ff6461811246ee943615375e01e9','8c6d01b65f56ec2c10a4811a7b62c210','d3c7b1de3604adcbe153c95e801e39d5']"

  strings:
    $hex_string = { 1f 50 e0 4f d0 20 ea 3a 69 10 a2 d8 08 00 2b 30 30 9d 19 00 2f 43 3a 5c 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 52 00 31 00 00 00 00 00 00 00 00 00 10 00 57 69 6e 64 6f 77 73 }

  condition:
    filesize > 1024 and filesize < 4096
    and $hex_string
}