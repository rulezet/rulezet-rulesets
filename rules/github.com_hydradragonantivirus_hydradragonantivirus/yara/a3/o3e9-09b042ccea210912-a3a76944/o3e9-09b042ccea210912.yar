rule o3e9_09b042ccea210912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.09b042ccea210912"
    cluster      = "o3e9.09b042ccea210912"
    cluster_size = "21"
    filetype     = "PE32 executable (GUI) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "installmonstr dlboost zusy"
    md5_hashes   = "['0ad180ec1f34ad4feb274a4c3a578ae8','1721b6f5fd8dfe21651ecf9de3f35acf','968dfe6503566d11c6463c881871877e']"

  strings:
    $hex_string = { 09 14 5d 7e 0b da 85 4f cc 4b 10 69 6c 99 e2 5e fc 9d a4 18 89 22 95 a6 87 97 f2 76 20 ee 77 a7 50 dd 3e 11 33 3b 6b a0 ae 7f a1 4c af e1 8f 19 c2 ed 4e 00 f6 cb 36 a8 ca 35 5c 16 f0 dc 61 96 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}