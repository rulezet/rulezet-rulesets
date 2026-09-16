rule k3e9_14e109921ee311b2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.14e109921ee311b2"
    cluster      = "k3e9.14e109921ee311b2"
    cluster_size = "17"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['07c89375a4b115a78efa72f0ab09af9e','327746f17f059dac5715aae4ca1e560c','dc6ecd2085cc875962e1e34a72bfe202']"

  strings:
    $hex_string = { 80 82 cc c8 77 77 77 78 00 86 7c 68 70 44 44 78 00 86 7f 78 70 cc c4 78 00 87 f7 b8 b0 bc c4 78 00 8f ff c8 bb 00 00 78 00 87 f7 bb fb b7 77 78 00 08 7f 22 bb 88 88 88 00 08 f7 6b b2 b2 22 20 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}