rule j3e7_63247246d932a852 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e7.63247246d932a852"
    cluster      = "j3e7.63247246d932a852"
    cluster_size = "3"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "zusy qakbot mewsspy"
    md5_hashes   = "['adbe3dc866dfa095a7f1fcda60424370','c4684bb82a235d0f183dba7c0383d002','d98c01b5dd360c9943251b65a12b3eca']"

  strings:
    $hex_string = { 4d 10 83 c7 04 89 39 eb 0b 79 06 4e 89 75 0c eb 03 8d 5e 01 3b 5d 0c 7e be 5f 5e 33 c9 85 c0 0f 94 c1 5b 8b c1 5d c3 8b ff 55 8b ec 51 85 f6 74 50 80 3e 00 74 4b 68 08 b9 43 00 56 e8 ce 9c ff }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}