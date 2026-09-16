rule o26bf_2994b049c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26bf.2994b049c0000b12"
    cluster         = "o26bf.2994b049c0000b12"
    cluster_size    = "9"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "temonde malicious kryptik"
    md5_hashes      = "['47f0828666562e19b04eb1fe60947a7e5bbe42b2','47710dd412a9188706e54952d863bf9bfaffcd70','fe3de0b1a2fd3cde5b771f31b615d2e6610c04f3']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26bf.2994b049c0000b12"

  strings:
    $hex_string = "coding=\"utf-8\"?>\r\n<assembly manifestVersion=\"1.0\" xmlns=\"urn:sch"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}