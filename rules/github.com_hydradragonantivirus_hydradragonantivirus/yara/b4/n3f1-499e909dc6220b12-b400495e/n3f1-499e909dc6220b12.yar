rule n3f1_499e909dc6220b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f1.499e909dc6220b12"
    cluster      = "n3f1.499e909dc6220b12"
    cluster_size = "26"
    filetype     = "application/zip"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "obfus androidos andr"
    md5_hashes   = "['0d0a49177f3f5d42be4980b7b9aa33db','1e97e5f3ba32b1115a5065784355ba50','984df08a0e5b1fdf91a93b07734d03fc']"

  strings:
    $hex_string = { 1c 81 40 ff ff 08 00 02 00 05 00 00 00 08 00 00 1c b5 51 3f ff 08 00 02 00 06 00 00 00 08 00 00 1c 9f 3f 30 ff 02 02 10 00 18 00 00 00 06 00 00 00 02 00 00 00 00 00 00 40 00 00 00 40 01 02 4c }

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}