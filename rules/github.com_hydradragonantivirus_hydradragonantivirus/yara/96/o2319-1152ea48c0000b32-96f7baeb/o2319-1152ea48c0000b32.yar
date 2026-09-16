rule o2319_1152ea48c0000b32 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=o2319.1152ea48c0000b32"
    cluster         = "o2319.1152ea48c0000b32"
    cluster_size    = "18"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180911"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "clickjack faceliker likejack"
    md5_hashes      = "['a3b6edb277589f02d4db3527b0c299beb19b55d5','98367b06aaf74be5e6891d9fa085931a9f164e90','d7d5aa5f2b20712e66706fb625695325dc864eae']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=o2319.1152ea48c0000b32"

  strings:
    $hex_string = "]*)\\s*\\]/g,\"='$1']\");if(!k.isXML(a))try{if(e||!l.match.PSEUDO.te"

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}