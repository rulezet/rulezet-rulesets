rule o26c0_511eea44c0000b12 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o26c0.511eea44c0000b12"
    cluster         = "o26c0.511eea44c0000b12"
    cluster_size    = "22"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180909"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "strictor malicious genkryptik"
    md5_hashes      = "['136683fafae4d00d099037591ffecc40023a80e7','da970c8c3c107879cc9c92a1bf01624bc292beaa','725223532c85a357d5e9aafa05784b75137306c5']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o26c0.511eea44c0000b12"

  strings:
    $hex_string = { c2 6a 20 83 e0 1f 59 2b c8 d3 cf 33 fa 87 3b 33 c0 5f 5e 5b 5d c3 8b ff 55 8b ec 8b 45 08 57 8d 3c 85 b0 b5 5c 00 8b 0f 85 c9 74 0b 8d 41 01 f7 d8 1b c0 23 c1 eb 57 53 8b 1c 85 d8 dc 40 00 56 }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}