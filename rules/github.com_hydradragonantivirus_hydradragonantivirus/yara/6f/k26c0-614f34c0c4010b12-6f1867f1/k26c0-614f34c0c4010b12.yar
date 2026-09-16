rule k26c0_614f34c0c4010b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k26c0.614f34c0c4010b12"
    cluster         = "k26c0.614f34c0c4010b12"
    cluster_size    = "11"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "fakeav malicious attribute"
    md5_hashes      = "['e2dcda5e14700a503eb49195b88b834fea781723','0ca7620d9fbf423d2b9d063eb3775df5910843de','9144b7c83f3e06f6764b798101bb76999ba682b3']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k26c0.614f34c0c4010b12"

  strings:
    $hex_string = { 00 00 25 4b 73 4b 27 4d 74 4d 26 48 8d 48 28 50 91 50 21 49 84 49 22 51 76 51 24 47 77 47 23 4f 75 4f 2d 52 92 52 2e 53 93 53 6b 4e 90 4e 6d 4a 8e 4a 7a 85 85 85 7b 86 86 86 bd 0c 0c 82 bb 0d }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}