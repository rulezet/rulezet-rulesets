rule CAPE_Rozena {
  meta:
    description = "No description has been set in the source file - CAPE"
    author      = "Kevin O'Reilly"
    id          = "38ca9da3-2a0e-500f-8eb8-9de69a7f2da5"
    date        = "2024-03-15"
    modified    = "2024-03-15"
    reference   = "https://github.com/kevoreilly/CAPEv2"
    source_url  = "https://github.com/kevoreilly/CAPEv2/blob/28da61aec456106a39ce5a81c1257f7cce7fb270/data/yara/CAPE/Rozena.yar#L1-L10"
    license_url = "https://github.com/kevoreilly/CAPEv2/blob/28da61aec456106a39ce5a81c1257f7cce7fb270/LICENSE"
    logic_hash  = "c415a8108b58a125a604031bb8d73b58a8aae5429b5b765e35fa8a4add9cd135"
    score       = 75
    quality     = 70
    tags        = ""
    cape_type   = "Rozena Payload"

  strings:
    $ip_port = { FF D5 6A 0A 68 [4] 68 [4] 89 E6 50 50 50 50 40 50 40 50 68 [4] FF D5 }
    $socket  = { 6A 00 6A 04 56 57 68 [4] FF D5 [0-5] 8B 36 6A 40 68 00 10 00 00 56 6A 00 68 }

  condition:
    all of them
}