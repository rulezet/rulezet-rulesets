rule n3f4_23991ec1c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f4.23991ec1c8000b12"
    cluster      = "n3f4.23991ec1c8000b12"
    cluster_size = "4"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "johnnie malicious kryptik"
    md5_hashes   = "['4e1d5b0b82bb3344e9822ee57a697b9a','617c854f18fe06e43cccc9bcb83fbfcf','911aa94bf9fc452521a16a2b00c29633']"

  strings:
    $hex_string = { 57 69 6e 64 6f 77 73 c2 a0 38 2e 31 20 2d 2d 3e 0d 0a 20 20 20 20 20 20 3c 21 2d 2d 3c 73 75 70 70 6f 72 74 65 64 4f 53 20 49 64 3d 22 7b 31 66 36 37 36 63 37 36 2d 38 30 65 31 2d 34 32 33 39 }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}