rule o3f9_6124c502924a4856 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3f9.6124c502924a4856"
    cluster      = "o3f9.6124c502924a4856"
    cluster_size = "31"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "lyposit zusy ransom"
    md5_hashes   = "['06d7c3f41d8de1ccf9d20524c1d699f3','14f523a73785486be19a74e74b24fbc4','b201835c36b009bd4b234f9509c30d66']"

  strings:
    $hex_string = { cb 0f f6 75 7a 04 c5 b5 e4 83 bc 92 6d 14 6e 95 98 e8 76 bb 97 8a 5e a8 26 01 91 28 d8 af d2 fe ea c6 89 a7 e5 4e f1 fb d6 a3 7f 06 71 a5 cf 5b e3 e0 10 c1 30 78 32 ad 8f b3 4a f3 5f 48 c0 bf }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}