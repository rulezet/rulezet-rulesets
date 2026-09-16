import "hash"
rule IOC_AMADEY_exe {
  meta:
    author     = "Laboratoire Epidemiology & Signal Intelligence"
    ref_IOC    = "IOC_AMADEY_LAB"
    date_IOC   = "2023-11-14 09:23:43"
    info       = "Version 1.0 b"
    internal   = false
    score      = 99
    risk_score = 10
    threat     = "AMADEY"
    file_type  = "exe"
    comment    = "Source : abuse.ch"

  condition:
    hash.sha256(0, filesize) == "a4528e6b733c6b595e93e3d50fb849edbe9fcd062b65fb2bd4ae5d8d76ac5b76" or
    hash.sha256(0, filesize) == "755cbdd175e237a66a78ed70d9d8a39c8946a57e64c199be154b86f528671d51" or
    hash.sha256(0, filesize) == "92b44334a248b6b3850c38fc3aadb63d0ae1828cc2a6617be41299eb4707d82e" or
    hash.sha256(0, filesize) == "75b6b00dcdb1025df8a76e02a7c989b5c6d670e0dcf1737be4f20641b89cde77" or
    hash.sha256(0, filesize) == "83ef6d2414a5c0c9cb6cfe502cb40cdda5c425ee7408a4075e32891f4599d938" or
    hash.sha256(0, filesize) == "6d3cd39358c91c56b4798b64c73f03e3877a80dffe01d07e2ad13e979e845ed0" or
    hash.sha256(0, filesize) == "75521cc92675383e1f9b8996fd925345e562da8b2a2aedb9cebacb9cc0ee0a80" or
    hash.sha256(0, filesize) == "d3a40144912dfa3f095ab0526aba7c0ce4950793090a632dc76f9fd93be815ab" or
    hash.sha256(0, filesize) == "831abc8d1a70104ae46b5c2c1ce6fce24ef449a03bde0d770a5a67f96ab22e7c"
}