rule o3e9_43b0c9ebc8801912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.43b0c9ebc8801912"
    cluster      = "o3e9.43b0c9ebc8801912"
    cluster_size = "60"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit nimnul bqjjnb"
    md5_hashes   = "['031f5954817c539922325099cc974418','043cd1fb7156c3112b91e24e43fab408','a42ef9a721da7369979c3611ba2c08ad']"

  strings:
    $hex_string = { 48 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23 24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33 34 35 36 37 38 39 3a 3b 3c 3d 3e }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}