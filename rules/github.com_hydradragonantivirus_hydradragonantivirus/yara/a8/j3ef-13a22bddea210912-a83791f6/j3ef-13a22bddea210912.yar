rule j3ef_13a22bddea210912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3ef.13a22bddea210912"
    cluster      = "j3ef.13a22bddea210912"
    cluster_size = "12"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "kranet malicious corrupt"
    md5_hashes   = "['0b7150ac2be179adf704c44821f1a5cc','28878659519b57512f57434aa1e8be54','fe8f90eb06e5cec4897e4eabd981a5f4']"

  strings:
    $hex_string = { 44 69 73 70 6c 61 79 4e 61 6d 65 20 4c 49 4b 45 20 27 54 41 50 2d 57 69 6e 25 27 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}