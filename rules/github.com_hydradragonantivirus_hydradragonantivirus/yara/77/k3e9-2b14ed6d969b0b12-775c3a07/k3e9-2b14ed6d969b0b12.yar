rule k3e9_2b14ed6d969b0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2b14ed6d969b0b12"
    cluster      = "k3e9.2b14ed6d969b0b12"
    cluster_size = "5"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba emotet vbkrypt"
    md5_hashes   = "['4697928ae402c98090dd2c430edf4ce4','8e3eff75faf2e867be7cc11a1b4567e1','bf2f787b0c8d551f0419334c64b55fbd']"

  strings:
    $hex_string = { 1e b0 06 2c 01 53 c0 04 a8 c2 1c 27 d9 30 c7 a9 43 1f 22 c7 b4 54 7f 4f 29 34 c3 74 fd bd 24 aa 4d fa 79 a5 ea ef 25 0a 19 c9 c8 48 a2 33 12 90 a1 d3 a7 36 77 6e be 35 5a af ee 8c 31 11 ed 58 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}