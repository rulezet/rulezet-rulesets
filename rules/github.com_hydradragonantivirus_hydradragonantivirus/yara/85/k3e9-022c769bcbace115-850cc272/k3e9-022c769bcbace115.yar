rule k3e9_022c769bcbace115 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.022c769bcbace115"
    cluster      = "k3e9.022c769bcbace115"
    cluster_size = "3"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171124"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "qukart backdoor berbew"
    md5_hashes   = "['acae9f9f543c0eb31e23a9eb7879f56e','ec4bf6e095f23ff8d2cb08b235fb2d91','fd8d871ab37b1d093680c7169cb19c1b']"

  strings:
    $hex_string = { 63 65 73 73 41 00 00 00 00 93 02 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 00 00 00 97 02 57 69 64 65 43 68 61 72 54 6f 4d 75 6c 74 69 42 79 74 65 00 00 00 98 02 57 69 6e 45 78 }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}