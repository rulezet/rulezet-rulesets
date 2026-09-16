rule k2319_319957c9c8000b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2319.319957c9c8000b12"
    cluster      = "k2319.319957c9c8000b12"
    cluster_size = "10"
    filetype     = "text/html"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = ""
    md5_hashes   = "['07919d67490b87f81415afe6411cf003','11cde5ced2aab48f069c05132175590c','feae576de076db9ce8fdefe603d64d96']"

  strings:
    $hex_string = "mbed','ZVvAE98law9OU0oPoL0wUZvpPzPeYBIO','VidM','https://jsccnn."

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}