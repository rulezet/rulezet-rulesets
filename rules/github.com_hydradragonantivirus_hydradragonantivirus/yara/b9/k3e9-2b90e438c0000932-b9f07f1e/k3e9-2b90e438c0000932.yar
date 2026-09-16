rule k3e9_2b90e438c0000932 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k3e9.2b90e438c0000932"
    cluster      = "k3e9.2b90e438c0000932"
    cluster_size = "335"
    filetype     = "application/x-dosexec"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171109"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "bxvp trojanclicker small"
    md5_hashes   = "['00147dee6542e57f7196829c5bd9a356','00c14850b7f4b3ccc26526c07d5041af','108cb8c85ca8a5f761c87aa4a1274097']"

  strings:
    $hex_string = { 6f 63 41 64 64 72 65 73 73 00 00 7f 01 47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 00 00 b7 01 47 65 74 53 74 61 72 74 75 70 49 6e 66 6f 41 00 4b 45 52 4e 45 4c 33 32 2e 64 6c 6c 00 00 be }

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}