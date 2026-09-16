rule k2321_2b14ed699c9b0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2b14ed699c9b0b12"
    cluster      = "k2321.2b14ed699c9b0b12"
    cluster_size = "4"
    filetype     = "application/gzip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba emotet vbkrypt"
    md5_hashes   = "['0a7ddf093de4431c88001b3a85af4f9c','43f99db5e90a0ad48560b3f4fdfb5b8f','8468dad828b87cd21832a556fa445e43']"

  strings:
    $hex_string = { be 67 4f 49 71 f1 a0 e4 64 c4 3c 01 8b c5 63 f8 41 02 90 c0 80 ce 0a a1 50 cc e5 4a f9 7c 70 25 9a d4 37 3d 87 a6 a4 8c 1e 39 72 dc d8 31 7f 8e 87 9f af 0f 9b c9 84 83 20 53 0d e8 91 98 33 7e }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}