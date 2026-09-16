rule n3f1_491e9e99c6200b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.491e9e99c6200b32"
    cluster      = "n3f1.491e9e99c6200b32"
    cluster_size = "7"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "androidos obfus andr"
    md5_hashes   = "['730a2c64adcb128a8dc03d019a1be58c','74e2ee82c174b43b7583c31ac9953478','f34fbf07dac341dfdacdfd5790f6ac2c']"

  strings:
    $hex_string = { 10 a0 33 3e e1 e7 72 d6 70 80 75 91 74 46 8b 08 5f 00 2c e3 c6 07 35 a7 96 e5 ea fa 6a b7 49 be 1f 7e f1 d3 1f d5 5a 6b d1 c0 15 09 d2 4e 22 63 9c 0e 64 bd d8 76 ad 05 11 d4 aa 58 1b 87 e2 f7 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}