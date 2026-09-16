rule k3e9_4563422679b34c37 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.4563422679b34c37"
    cluster      = "k3e9.4563422679b34c37"
    cluster_size = "9"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['3906f6c9b4d29de68f9d4c0c72b4ee7c','a0e480ff2137d12d026cd96d976af86f','cea261b8f55614c170f9aed2f30657d7']"

  strings:
    $hex_string = { 1a 33 c9 83 f8 7a 0f 94 c1 49 81 e1 f7 3f f9 ff 81 c1 0e 00 07 80 89 4d fc eb 1b c7 45 fc 57 00 07 80 eb 12 57 50 83 c6 08 56 51 ff 15 90 60 00 01 39 5d fc 74 12 8b 75 08 8b 06 3b c3 74 09 50 }

  condition:
    filesize > 65536 and filesize < 262144
    and $hex_string
}