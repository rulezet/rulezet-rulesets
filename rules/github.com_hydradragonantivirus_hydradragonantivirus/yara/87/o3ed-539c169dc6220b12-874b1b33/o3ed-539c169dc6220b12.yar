rule o3ed_539c169dc6220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3ed.539c169dc6220b12"
    cluster      = "o3ed.539c169dc6220b12"
    cluster_size = "1597"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit nimnul bpchjo"
    md5_hashes   = "['00d1a7e544a875f94b99cd8a3e1c3bfe','00d5a965195dda7ba571ca25acc5e0ad','03a12173fce75e1fdcca27620d4d9533']"

  strings:
    $hex_string = { 66 83 3e 2e 74 ba 56 57 ff 15 f4 e3 14 10 59 59 b0 01 5e eb 02 32 c0 8b 4d fc 5f 33 cd 5b e8 29 2a 05 00 c9 c2 0c 00 55 8d ac 24 64 fc ff ff 81 ec 1c 04 00 00 a1 28 c8 19 10 33 c5 89 85 98 03 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}