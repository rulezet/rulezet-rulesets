rule k3e9_092b311e43ea8912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.092b311e43ea8912"
    cluster      = "k3e9.092b311e43ea8912"
    cluster_size = "12"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "jeefo hidrag adload"
    md5_hashes   = "['195ee40ddb590fdcc76902fe54e93382','1a2dbd398405da5d52f7c78a3542b821','fefe2e97f5b0e384c7267fab6000e655']"

  strings:
    $hex_string = { e1 32 e3 56 e5 55 e7 4c e9 5f eb 4f ed 62 ef 3e f1 53 f3 61 f5 5b f7 f8 f9 fa fb 49 fd 67 ff 63 01 74 03 73 05 79 07 77 09 70 0b 80 0d bc 0f 30 11 69 13 7d 15 84 17 7c 19 89 1b 93 1d 91 1f ce }

  condition:
    filesize > 4194304 and filesize < 16777216
    and $hex_string
}