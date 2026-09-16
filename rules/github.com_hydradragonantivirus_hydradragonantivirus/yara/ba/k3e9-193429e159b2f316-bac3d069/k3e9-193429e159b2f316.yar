rule k3e9_193429e159b2f316 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.193429e159b2f316"
    cluster      = "k3e9.193429e159b2f316"
    cluster_size = "68"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installcore advml attribute"
    md5_hashes   = "['04f0c969a66f3872107f0697e9ccc148','0993c4946b3afb7f395a268137dd92fd','39c54cb90077fb940ecd101578e9db4c']"

  strings:
    $hex_string = { 30 ce 0e c8 e5 fb b6 73 7c 2c 29 f2 09 d0 be af a9 4c 1c ec 04 c0 06 96 64 a0 37 20 5e 3b 45 79 42 15 7f 66 55 48 13 71 f0 b3 7a 44 56 fe bb 77 cf 85 a6 35 f1 6a d1 a5 8c b4 39 e6 5c 50 14 10 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}