rule apt37_rokrat_macho {
  meta:
    id             = "c54fb9ae-85fa-4c36-bab9-6c6d989262ba"
    version        = "1.0"
    description    = "Detects Public key of Macho samples of RokRAT"
    author         = "Sekoia.io"
    creation_date  = "2022-09-29"
    classification = "TLP:CLEAR"

  strings:
    $s1 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsGRYSEVvwmfBFNBjOz+Q"
    $s2 = "pax5rzWf/LT/yFUQA1zrA1njjyIHrzphgc9tgGHs/7tsWp8e5dLkAYsVGhWAPsjy"
    $s3 = "1gx0drbdMjlTbBYTyEg5Pgy/5MsENDdnsCRWr23ZaOELvHHVV8CMC8Fu4Wbaz80L"
    $s4 = "Ghg8isVPEHC8H/yGtjHPYFVe6lwVr/MXoKcpx13S1K8nmDQNAhMpT1aLaG/6Qijh"
    $s5 = "W4P/RFQq+Fdia3fFehPg5DtYD90rS3sdFKmj9N6MO0/WAVdZzGuEXD53LHz9eZwR"
    $s6 = "9Y8786nVDrlma5YCKpqUZ5c46wW3gYWi3sY+VS3b2FdAKCJhTfCy82AUGqPSVfLa"
    $s7 = "mQIDAQAB"

  condition:
    all of them
}