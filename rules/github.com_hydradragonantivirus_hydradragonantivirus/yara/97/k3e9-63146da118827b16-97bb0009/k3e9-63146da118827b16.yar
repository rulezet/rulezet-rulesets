rule k3e9_63146da118827b16 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.63146da118827b16"
    cluster      = "k3e9.63146da118827b16"
    cluster_size = "49"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['1facfd4500d5a17bc8af43c04509aca1','26097f2a871494a28ce65276f2f9b537','b0a2716f14523d6f87cccd28421cb2f0']"

  strings:
    $hex_string = { 00 77 00 73 00 28 00 54 00 4d 00 29 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00 00 00 3e 00 0d 00 01 00 50 00 72 00 6f 00 64 00 75 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}