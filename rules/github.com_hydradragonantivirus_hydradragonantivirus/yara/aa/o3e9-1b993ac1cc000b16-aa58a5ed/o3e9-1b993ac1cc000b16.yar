rule o3e9_1b993ac1cc000b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.1b993ac1cc000b16"
    cluster      = "o3e9.1b993ac1cc000b16"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock nabucur polyransom"
    md5_hashes   = "['39cc5fe21f47f3acf8825c8ba8c9d6b7','bfac84b9e528fa0773b3e68eb21ce38e','d147694d5ae3f4800c158f7e20fb409f']"

  strings:
    $hex_string = { 7e 01 02 02 02 29 e9 b7 8f ff 9d ae f4 ff 2c 54 f1 ff 09 38 f2 ff 11 3f f3 ff 11 3f f3 ff 1f 3a fe ff 00 b6 80 ff 00 b7 67 ff 00 9e 61 ff 00 8e 55 ff 26 8c 67 ff 84 a3 98 ff da c5 b5 ff fa e4 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}