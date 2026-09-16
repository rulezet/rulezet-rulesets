rule o3e9_5992bec9c4000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.5992bec9c4000932"
    cluster      = "o3e9.5992bec9c4000932"
    cluster_size = "16"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock tdss nabucur"
    md5_hashes   = "['0fd4b90b122b109e97ba5cd0f720f9e0','468689ee239888da9825bdc71f435aaf','e155319a9001dc968c209ea35a16f386']"

  strings:
    $hex_string = { 00 5b 8f ef 00 57 7c dd 00 2d 59 de 00 40 6e ca 00 70 ad ed 00 72 a7 ea 00 60 94 d7 00 26 64 c9 00 5a 89 d1 00 65 95 d0 00 20 2e 43 00 4b 85 ba 00 85 81 8b 00 cc 70 0d 00 d6 71 03 00 d3 73 08 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}