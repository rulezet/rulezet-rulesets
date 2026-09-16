rule o3e9_1539ac6a9e436d1a {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.1539ac6a9e436d1a"
    cluster      = "o3e9.1539ac6a9e436d1a"
    cluster_size = "374"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonster installmonstr malicious"
    md5_hashes   = "['010cfcde819443f340b4c6bc4425b23f','01a38f90b984dd06a0fb2e5f3a159910','09f8268d27851b23861b339bc1c49e18']"

  strings:
    $hex_string = { 06 2a d2 0d d4 6e db a9 97 9a 60 8c 6f ea fe af 5d 12 2c b4 f5 19 3f 7b 04 63 de ec 35 bc dc ed a2 ea a4 ff e4 c9 63 f8 5a ba 59 1a 74 df 60 b3 12 79 c9 0d 3c e3 4e 22 ca b6 7c 06 f2 26 92 75 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}