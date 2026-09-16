rule o26c9_45b4e44980000932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c9.45b4e44980000932"
    cluster         = "o26c9.45b4e44980000932"
    cluster_size    = "401"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "coinminer malicious autoit"
    md5_hashes      = "['f0652f719ab1acff5aa919cc4d323f8dae935f0c','991eaf2ad27282707031db29a1661c2d947bec13','2bd38f0d2dac27132c0871325c18186b9340a73c']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c9.45b4e44980000932"

  strings:
    $hex_string = { 89 59 08 44 3b d9 72 45 41 81 fb 00 01 00 00 73 04 85 ff 74 38 41 8b c3 48 8d 1d 8a 2b fa ff 99 f7 f9 48 63 c8 48 63 c2 44 0f b6 84 19 c0 7b 0c 00 49 c1 e0 07 4c 03 c0 42 0f b7 84 43 c0 b0 0b }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}