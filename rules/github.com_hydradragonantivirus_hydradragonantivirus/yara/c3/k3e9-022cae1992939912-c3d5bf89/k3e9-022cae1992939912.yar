rule k3e9_022cae1992939912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.022cae1992939912"
    cluster      = "k3e9.022cae1992939912"
    cluster_size = "3"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "qukart backdoor berbew"
    md5_hashes   = "['c42511e3dd51b99a232767268f5f4dcb','cd2f404067f54149cd23d2dcfd05c11e','ec527391f2679a8a962774ce8eaf13a5']"

  strings:
    $hex_string = { cd 01 53 65 74 53 65 63 75 72 69 74 79 49 6e 66 6f 00 00 00 d4 01 53 65 74 45 6e 74 72 69 65 73 49 6e 41 63 6c 41 00 00 18 00 5f 5f 47 65 74 4d 61 69 6e 41 72 67 73 00 81 01 5f 73 6c 65 65 70 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}