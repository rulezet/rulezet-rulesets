rule k3e9_50b131161da31132 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.50b131161da31132"
    cluster      = "k3e9.50b131161da31132"
    cluster_size = "5"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['be3b354bd12d3d001dca3ff02baa43c3','c29399e2e2da9d000b20ad87b2aba3da','f327b9dcd3c7a6fcd46c0e3aa338d4be']"

  strings:
    $hex_string = { 00 03 00 01 50 00 00 00 00 28 00 53 00 56 00 0a 00 e8 03 ff ff 80 00 26 00 44 00 6f 00 6e 00 27 00 74 00 20 00 72 00 65 00 6d 00 69 00 6e 00 64 00 20 00 6d 00 65 00 20 00 61 00 67 00 61 00 69 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}