rule j2321_1916168eee650932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j2321.1916168eee650932"
    cluster      = "j2321.1916168eee650932"
    cluster_size = "4"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "cdvq ageneric backdoor"
    md5_hashes   = "['1da38fa93004defad6ab83243e33f67b','22fc193f8cafa272f5286ed2b125e871','d6b18970acdfc9a87f095479cb583d0a']"

  strings:
    $hex_string = { 6f 5f a2 1f c5 30 9b 37 74 38 43 22 68 ed 0f 3c 87 d3 00 fa 0e 24 06 51 1c ac 03 1b c2 90 a1 b4 46 02 cf e0 34 8c be 51 c4 70 8a 23 6c de 82 23 19 32 8a d6 d1 40 2a 9c c6 d0 77 2c 31 8e e2 78 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}