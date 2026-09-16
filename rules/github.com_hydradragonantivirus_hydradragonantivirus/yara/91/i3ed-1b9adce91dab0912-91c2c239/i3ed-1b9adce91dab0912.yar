rule i3ed_1b9adce91dab0912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=i3ed.1b9adce91dab0912"
    cluster      = "i3ed.1b9adce91dab0912"
    cluster_size = "43"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171117"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "backdoor padodor symmi"
    md5_hashes   = "['03f1d63b7cf5a9bef64e100d495388a6','0ea1b34efe9d748fe4ee776f8a9577da','a433881a8d8fb31598aacee6ddd3b6cd']"

  strings:
    $hex_string = { 7b 08 8d 0c 76 8b 34 8f e9 62 ff ff ff 31 c0 eb 19 55 8d 6b 10 6a ff 53 e8 a5 fe ff ff 83 c4 0c 6a 0b e8 53 04 00 00 83 c4 04 5d 5f 5e 5b 89 ec 5d c3 55 89 e5 53 56 57 83 7d 0c 01 75 05 e8 23 }

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}