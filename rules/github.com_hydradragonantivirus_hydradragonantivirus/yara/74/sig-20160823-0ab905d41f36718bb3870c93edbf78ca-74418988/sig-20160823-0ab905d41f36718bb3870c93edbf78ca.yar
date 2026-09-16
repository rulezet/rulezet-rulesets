rule sig_20160823_0ab905d41f36718bb3870c93edbf78ca {
  meta:
    description = "datamaliciousorder - file 20160823_0ab905d41f36718bb3870c93edbf78ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a8f5c482ed2eefeccba497e2ed9ec8dd7c3a4a8dae80dd37f15862eae9c707d"

  strings:
    $s1 = "var Ha8 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}