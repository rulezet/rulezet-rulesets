rule n3ee_039f6a48c4000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3ee.039f6a48c4000932"
    cluster      = "n3ee.039f6a48c4000932"
    cluster_size = "83"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "ramnit nimnul patched"
    md5_hashes   = "['00def032ccc6a47ffdb39d4b0cb824d4','012669e85679bdec44d63adc4b031eeb','0fa99d987865babbd666d13a240847c0']"

  strings:
    $hex_string = { 04 8a 58 2d 88 1c 0e 66 ff 40 0c 8b 70 30 6a 10 59 2b ce d3 fa 8d 4c 3e f0 5b 66 89 50 2c eb 08 d3 e2 66 09 50 2c 03 cf 89 48 30 5e c3 8b ff 55 8b ec 33 c0 0f b6 4d 08 d1 7d 08 83 e1 01 0b c1 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}