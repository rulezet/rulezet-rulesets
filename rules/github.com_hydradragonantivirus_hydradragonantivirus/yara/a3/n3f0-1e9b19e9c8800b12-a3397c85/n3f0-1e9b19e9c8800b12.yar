rule n3f0_1e9b19e9c8800b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f0.1e9b19e9c8800b12"
    cluster      = "n3f0.1e9b19e9c8800b12"
    cluster_size = "7436"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "generickd mira otorunp"
    md5_hashes   = "['000eb6dee5b7dcc69ea4fc103878e405','001c456ebf716d335de00170c45e61d0','00dd0876e5f9a6769b86132cc8da6ce7']"

  strings:
    $hex_string = { d8 01 e4 e2 33 1a 29 18 95 a9 ce 3f 3d 47 9e aa 09 cb b5 45 ff 5a 39 59 ef e4 20 7f 43 5d 7b 24 04 50 fe 1a 65 d1 2b ba ad ca 63 82 88 27 fe e8 59 be 58 25 63 fe 9e 6b b3 d4 cb ba 3e 61 88 7f }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}