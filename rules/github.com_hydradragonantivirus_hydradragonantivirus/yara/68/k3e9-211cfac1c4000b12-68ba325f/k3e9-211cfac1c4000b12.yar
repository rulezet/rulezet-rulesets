rule k3e9_211cfac1c4000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.211cfac1c4000b12"
    cluster      = "k3e9.211cfac1c4000b12"
    cluster_size = "4646"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor bgtuw darkkomet"
    md5_hashes   = "['000581fc1944412e45880cd9d5d78c5d','0011ee54fb4228d0cbb1d6529e8702f4','00cae18a5c7e6c60b2e7c11967b87c72']"

  strings:
    $hex_string = { 85 c0 74 3a 3b f0 73 22 83 7d fc 00 0f 84 b1 03 00 00 0f b6 02 ff 4d fc 8b ce d3 e0 42 83 c6 08 89 55 f8 03 d8 3b 77 48 72 de 8b 4f 48 b8 01 00 00 00 d3 e0 48 23 c3 01 47 40 d3 eb 2b f1 c7 07 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}