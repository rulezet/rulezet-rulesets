rule n3f4_2b101022dabf4912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=n3f4.2b101022dabf4912"
    cluster      = "n3f4.2b101022dabf4912"
    cluster_size = "7"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171111"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "kryptik malicious tuto"
    md5_hashes   = "['1593334bb8a2e2a231173a55c3e83380','3b489385a855a295011889ec9f25581a','e74655d372e1a8affcd2fd02d3b86def']"

  strings:
    $hex_string = "FNMMHCVYah9wp7dR9bitK6idIW1vPAfe6Elgo84a2SJst5y8LKfQD6+XE3UqG/Ju"

  condition:
    filesize > 262144 and filesize < 1048576
    and $hex_string
}