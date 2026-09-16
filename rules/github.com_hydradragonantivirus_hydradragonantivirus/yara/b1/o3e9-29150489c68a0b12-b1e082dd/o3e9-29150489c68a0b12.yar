rule o3e9_29150489c68a0b12 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.29150489c68a0b12"
    cluster      = "o3e9.29150489c68a0b12"
    cluster_size = "327"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "blackv malicious noobyprotect"
    md5_hashes   = "['00e817c37401cfce76a72311d6338bc2','00ebea633d1ba23d244ae66bb8c4296d','0e4e9833488c23cc8943642fdcc42e6d']"

  strings:
    $hex_string = { 95 14 2a 9d 28 16 1f b0 8c 5f 02 4d 2a 36 7d 18 9c ea 6e a1 a8 df b2 a9 00 d8 0a 45 3f 20 d0 43 57 c8 ce d4 83 ce 98 db 9c 37 c0 ab e9 be 13 f2 c8 76 73 3d 80 37 71 8d 36 96 b2 9e 4b c8 6d 9c }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}