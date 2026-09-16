rule j3e7_7194d6c348000330 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3e7.7194d6c348000330"
    cluster      = "j3e7.7194d6c348000330"
    cluster_size = "774"
    filetype     = "application/octet-stream"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "shedun androidos risktool"
    md5_hashes   = "['000185e407296a9ef445aa1963b72c61','0032e04a9a130966d4d7796861b655fe','049f95fb1c8a6dda8523f8dff09b5369']"

  strings:
    $hex_string = { 63 74 2f 46 69 65 6c 64 3b 00 1a 4c 6a 61 76 61 2f 6c 61 6e 67 2f 72 65 66 6c 65 63 74 2f 4d 65 74 68 6f 64 3b 00 15 4c 6a 61 76 61 2f 75 74 69 6c 2f 41 72 72 61 79 4c 69 73 74 3b 00 16 4c 6a }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}