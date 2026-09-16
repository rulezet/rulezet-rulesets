rule o3e9_493c1ac9cc000912 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=o3e9.493c1ac9cc000912"
    cluster      = "o3e9.493c1ac9cc000912"
    cluster_size = "4"
    filetype     = ""
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171122"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "virlock nabucur malicious"
    md5_hashes   = "['afe0f9dd05a2397b1aab196aa1298d53','b8ab661cd49c5ebfd5ce37fba2ae1761','cadd1fe00eb2850f9848f5e10581b37a']"

  strings:
    $hex_string = { 80 91 ff ab 81 92 ff a2 88 9e ff 9c 8f a7 ff 93 9e ba ff 89 ac cb ff 71 cf f8 ff 74 c8 f1 ff 89 aa ca ff b9 7f 85 ff cf 89 62 ff fe d6 ad ff fc d1 be ff db 96 8b ff 33 1a 0d 8c 35 1b 0e 3c 3f }

  condition:
    filesize > 1048576 and filesize < 4194304
    and $hex_string
}