rule sig_20170504_ef06c4204f609e446665c7dad0db15cf {
  meta:
    description = "datamaliciousorder - file 20170504_ef06c4204f609e446665c7dad0db15cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "744f4288e17324a470d00a7241459f05f25a6d5941b95a1940991220ecc00b69"

  strings:
    $s1 = "this[\"\\x65\\166\\x61\\154\"](\"\\x6e\\145w\\x20\\u0041c\\x74\\151\\x76\\x65\\x58O\\x62j\\145\\x63\\164\\u0028\\x22\\u0057\\u00" ascii
    $s2 = "this[\"\\x65\\166\\x61\\154\"](\"\\x6e\\145w\\x20\\u0041c\\x74\\151\\x76\\x65\\x58O\\x62j\\145\\x63\\164\\u0028\\x22\\u0057\\u00" ascii

  condition:
    uint16(0) == 0x6874 and
    all of them
}