rule j3f4_23a0dde9c8800112 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=j3f4.23a0dde9c8800112"
    cluster      = "j3f4.23a0dde9c8800112"
    cluster_size = "36"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171123"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "dotdo engine malicious"
    md5_hashes   = "['03855c7290a2bbce687a9f89fecf685f','09856feef69bc640ddcb82f82874f3f9','93238d41d2dcd375f257a01808317514']"

  strings:
    $hex_string = "<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>-->\r\n\r"

  condition:
    filesize > 4096 and filesize < 16384
    and $hex_string
}