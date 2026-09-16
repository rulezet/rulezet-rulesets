rule sig_20160504_6acc5980f40ba012eecb9cdd3fa35773 {
  meta:
    description = "datamaliciousorder - file 20160504_6acc5980f40ba012eecb9cdd3fa35773.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cfc7558c451feca0b0e533305665fc62a3cbd05af8ee50157a72adac99e1541"

  strings:
    $s1 = "date';var a88='pt ';k55+=' a';var n1='tx';k55+='ntiv';var a64='pr *';k55+='irus';var g74='Cry';k55+=' s';var z10='sca';k55+='oft" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}