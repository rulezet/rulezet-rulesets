rule k3e9_45e52930a80444f2 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.45e52930a80444f2"
    cluster      = "k3e9.45e52930a80444f2"
    cluster_size = "37"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['1269cfe7e26446c74a488dd9b0502aea','366499e251c90971f1816c4ac32fa452','a9ea6cc6eb91c166cc6066a7a237da09']"

  strings:
    $hex_string = { 5e 65 af 05 78 86 82 7e 3e 48 4a 4e a6 43 30 57 5b 63 af 0b 7d 89 8b 8a 4d 4b 49 6a 55 51 38 58 5c 64 af 29 88 8c 8d 92 6d 31 3c 3a 53 50 3b 59 5d 17 05 76 8f 8e 90 94 84 56 47 3f 02 34 37 6c }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}