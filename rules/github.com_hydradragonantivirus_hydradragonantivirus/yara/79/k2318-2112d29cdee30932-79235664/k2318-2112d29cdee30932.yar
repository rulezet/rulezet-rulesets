rule k2318_2112d29cdee30932 {
  meta:
    copyright       = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine          = "saphire/1.3.8 divinorum/0.9992 icewater/0.4"
    viz_url         = "http://icewater.io/en/cluster/query?h64=k2318.2112d29cdee30932"
    cluster         = "k2318.2112d29cdee30932"
    cluster_size    = "15"
    filetype        = ""
    tlp             = "amber"
    version         = "icewater snowflake"
    author          = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date            = "20180910"
    license         = "RIL-1.0 [Rick's Internet License]"
    family          = "redirector iframe html"
    md5_hashes      = "['787620b4fc24a4fb8e9b0b812cb23cb9b41aaae9','8aed6e23e6d5428a2e7e7ea73cf1218e03ab9db8','0b91de4854796c0e17ea6c9e25ca8fc311fc5d31']"
    cluster_members = "http://icewater.io/en/cluster/detail?h64=k2318.2112d29cdee30932"

  strings:
    $hex_string = ".submit();\" size=\"1\" style=\"width: 100%\"><option value=\"\" SELECT"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}