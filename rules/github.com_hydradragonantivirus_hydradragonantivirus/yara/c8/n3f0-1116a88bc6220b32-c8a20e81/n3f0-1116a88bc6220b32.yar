rule n3f0_1116a88bc6220b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f0.1116a88bc6220b32"
    cluster      = "n3f0.1116a88bc6220b32"
    cluster_size = "9467"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "autorun backdoor injector"
    md5_hashes   = "['00003f306b6c2c46bea1b9bd9c66a5fe','0002891481ec0980f879a4787d3f31c7','00a33e7cdf9a768d485eb928fff60bdf']"

  strings:
    $hex_string = { 0d 82 c1 48 1f b7 63 02 39 62 8b 26 7a 6c 7c 83 62 3d 6e cf 7b da a4 d9 71 f2 b9 1e 12 4c 1b e8 25 3c 7a 7a d5 8a 76 b4 0d 05 27 44 ec 9e 39 61 4e 67 5e 4d 2a 86 11 a9 68 1b 96 26 51 02 20 cc }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}