rule o3e9_09993ec1cc000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.09993ec1cc000b32"
    cluster      = "o3e9.09993ec1cc000b32"
    cluster_size = "3"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock nabucur malicious"
    md5_hashes   = "['a26ca617f4da54b40486b179e38cb67b','ad89d7a624dac408a301f6d766a113d2','c0276dff6be34e463e51b063b49ed99e']"

  strings:
    $hex_string = { 3e 02 fb fb f9 79 94 a8 f2 ff 08 38 f5 ff 32 5b fe ff 53 76 fe ff 73 8e fe ff 8b a3 f8 ff a4 b4 ec ff b6 bc df ff bc c6 d4 ff af d7 ca ff 8e dc be ff 4a d2 9c ff 0f bc 79 ff 00 a7 6b ff 03 98 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}