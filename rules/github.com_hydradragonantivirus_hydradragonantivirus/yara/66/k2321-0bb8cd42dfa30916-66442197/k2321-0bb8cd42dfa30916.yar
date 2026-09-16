rule k2321_0bb8cd42dfa30916 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2321.0bb8cd42dfa30916"
    cluster      = "k2321.0bb8cd42dfa30916"
    cluster_size = "4"
    filetype     = "PE32 executable (console) Intel 80386"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "jtlp kryptik hupigon"
    md5_hashes   = "['107ede5aa266e67a1cc30974318a40f9','399afb24033e7fb1ca26513ca6eb7ace','de537440fd8cec123fbc7b5ac28e11e1']"

  strings:
    $hex_string = { 6b 8f be ec 58 af b3 bb e8 9e 9a f9 47 16 22 9d a0 96 d1 e2 ba f0 b5 a9 a2 55 89 41 27 db ae 5d 68 b0 4b 3f 10 53 e7 79 d6 6c f8 71 0a cd de dd 62 ad 1d 36 9f 88 4b bc cf b6 3e c8 38 26 bd 5b }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}