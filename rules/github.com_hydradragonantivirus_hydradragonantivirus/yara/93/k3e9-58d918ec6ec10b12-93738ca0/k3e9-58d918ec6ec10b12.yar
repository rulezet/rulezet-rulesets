rule k3e9_58d918ec6ec10b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.58d918ec6ec10b12"
    cluster      = "k3e9.58d918ec6ec10b12"
    cluster_size = "8"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171118"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "nitol kazy microfake"
    md5_hashes   = "['3a5e974a30a23c1aa0bc159191065059','87d0b6555f8993b646448699a99a59c4','f06ec1f5a78217ae87430427d337b9ab']"

  strings:
    $hex_string = { 10 72 2d 2b 44 24 10 3d 00 dd 6d 00 77 22 ff 15 78 20 00 10 3b 44 24 14 75 16 55 ff 35 9c 32 00 10 ff d7 3b c3 74 d4 33 c0 5f 5e 5d 5b 59 59 c3 33 c0 40 eb f4 55 8b ec 81 ec 68 06 00 00 53 6a }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}