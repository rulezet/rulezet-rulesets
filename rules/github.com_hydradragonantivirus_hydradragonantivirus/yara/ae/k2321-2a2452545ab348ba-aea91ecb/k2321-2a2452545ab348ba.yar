rule k2321_2a2452545ab348ba {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.2a2452545ab348ba"
    cluster      = "k2321.2a2452545ab348ba"
    cluster_size = "28"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "tinba zusy flmp"
    md5_hashes   = "['02d0c17ca800b03c60454c92f7beee79','1400b6ef5d89d4b9c7c2eccc92b6beae','a9f716ef72b2ffbf37ef1f020edf647c']"

  strings:
    $hex_string = { 0d 25 a8 a4 c9 2c 41 2b f8 4a d6 f5 79 e5 ab 5e e3 9c 83 7b 77 9c 96 c0 05 50 6a 8d bf 58 2b 3c ac f1 17 69 a2 84 fa 5d 64 34 57 cc b4 ec 6e 9a 36 98 99 01 78 46 a1 95 4c 9f 70 cd cf af e4 87 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}