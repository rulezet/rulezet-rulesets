rule j2321_2356339ada4f4b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.2356339ada4f4b12"
    cluster      = "j2321.2356339ada4f4b12"
    cluster_size = "3"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "upatre bublik generickd"
    md5_hashes   = "['5586c90415562804d48c41e95ce709b5','931d6310bd68bb87c2c468fb5be2ef47','c277b32ee64a6a268b6b3c7be4fac137']"

  strings:
    $hex_string = { 46 06 7a 3e 50 ca 28 0f b9 a2 a0 4f 6c bd 89 11 53 1e 2d fd f7 73 c3 19 1b b4 69 d1 1d 82 a4 63 e4 a8 d3 81 92 0d b9 4a 70 aa c1 97 8e 77 7f 6b 3f b1 1b 38 f2 04 79 2c 23 32 6a 9b 80 c4 b7 e3 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}