rule p3e9_519abb49c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=p3e9.519abb49c8000b12"
    cluster      = "p3e9.519abb49c8000b12"
    cluster_size = "90"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock nabucur ransom"
    md5_hashes   = "['0763bbc00ecd4f06f79c259b44844d16','12dee118e2633247105f22cf0e0532e0','a2b405b99adfc50bc21cb96fb9eec74c']"

  strings:
    $hex_string = { 7e 01 02 02 02 29 e9 b7 8f ff 9d ae f4 ff 2c 54 f1 ff 09 38 f2 ff 11 3f f3 ff 11 3f f3 ff 1f 3a fe ff 00 b6 80 ff 00 b7 67 ff 00 9e 61 ff 00 8e 55 ff 26 8c 67 ff 84 a3 98 ff da c5 b5 ff fa e4 }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}