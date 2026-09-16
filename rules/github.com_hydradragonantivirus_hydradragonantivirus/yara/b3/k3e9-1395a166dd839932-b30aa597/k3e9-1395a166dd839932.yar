rule k3e9_1395a166dd839932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.1395a166dd839932"
    cluster      = "k3e9.1395a166dd839932"
    cluster_size = "135"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virut virtob virux"
    md5_hashes   = "['0633313962e287e7e457122708bf141e','063ea954c3aefb203b5d481aa93f4c44','7fd6bbd64df5ea03bcf78412f207c0f6']"

  strings:
    $hex_string = { 5c 6a cc 4d ba 33 2b 1b c4 42 0a 57 32 45 14 96 bd c2 9d 40 8f 3e f2 ef ed a7 b4 fb b2 6f 5e 2f 65 d7 8e 45 be 53 03 1a f5 e4 26 9b 12 75 e8 84 76 77 59 4f b1 19 16 5d ee 47 e6 0a c5 8c 69 89 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}