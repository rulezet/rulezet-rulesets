rule j3eb_3901580200000000 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3eb.3901580200000000"
    cluster      = "j3eb.3901580200000000"
    cluster_size = "48"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "crypt kryptik malicious"
    md5_hashes   = "['25253fdf2038969c3378d27e1aaca637','269376e5c67a607eee465add744588e3','75c03f0a61a9c88715ad7acb2ef0dae3']"

  strings:
    $hex_string = { 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f 74 20 62 65 20 72 75 6e 20 69 6e 20 44 4f 53 20 6d 6f 64 65 2e 0d 0d 0a 24 00 00 00 00 00 00 00 39 24 11 dd 7d 45 7f 8e }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}