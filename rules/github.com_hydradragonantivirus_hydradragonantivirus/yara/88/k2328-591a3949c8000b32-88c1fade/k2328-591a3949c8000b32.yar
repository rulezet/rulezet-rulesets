rule k2328_591a3949c8000b32 {
  meta:
    copyright    = "Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
    engine       = "saphire/1.3.1 divinorum/0.998 icewater/0.4"
    viz_url      = "http://icewater.io/en/cluster/query?h64=k2328.591a3949c8000b32"
    cluster      = "k2328.591a3949c8000b32"
    cluster_size = "10"
    filetype     = "application/xml"
    tlp          = "amber"
    version      = "icewater snowflake"
    author       = "Rick Wesson (@wessorh) rick@support-intelligence.com"
    date         = "20171120"
    license      = "RIL-1.0 [Rick's Internet License] "
    family       = "fakejquery script classic"
    md5_hashes   = "['0d944bfc592ab656fe4d27df1642795c','4be46295241a6246f19d94f6ad11ee18','f15506f9e309d551ab414c2917bfd9ea']"

  strings:
    $hex_string = "xml version=\"1.0\" encoding=\"utf-8\"?><!DOCTYPE html PUBLIC \"-//W3"

  condition:
    filesize > 16384 and filesize < 65536
    and $hex_string
}