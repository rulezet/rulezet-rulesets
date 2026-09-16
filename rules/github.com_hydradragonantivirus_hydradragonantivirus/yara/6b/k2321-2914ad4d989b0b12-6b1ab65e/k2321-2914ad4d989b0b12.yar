rule k2321_2914ad4d989b0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2914ad4d989b0b12"
    cluster      = "k2321.2914ad4d989b0b12"
    cluster_size = "12"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba vbkrypt emotet"
    md5_hashes   = "['2cf70df1f7c74bea9ad6bfda85677bb8','32dea73ef4a8b3a67e7441ba3150293f','ffa355ce0d15b0a6697123f2cd329075']"

  strings:
    $hex_string = { 96 45 3a 0b 48 b9 40 dd 50 8a 1c 07 e7 45 54 53 d4 17 2b ea 0a 11 f4 65 b5 f9 04 92 ca 19 e2 aa e9 a2 86 99 42 f3 0c fe f9 c9 1c 34 62 2f f6 66 4c 4f 90 74 8b 08 82 81 32 a9 14 1d 9d 80 d3 36 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}