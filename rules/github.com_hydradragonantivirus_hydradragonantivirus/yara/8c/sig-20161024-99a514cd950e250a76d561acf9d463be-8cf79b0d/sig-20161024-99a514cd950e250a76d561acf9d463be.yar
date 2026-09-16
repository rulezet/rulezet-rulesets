rule sig_20161024_99a514cd950e250a76d561acf9d463be {
  meta:
    description = "datamaliciousorder - file 20161024_99a514cd950e250a76d561acf9d463be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "773e1c6c0277907ca696fee947c5db5142e30d97262a2843c39d28ed1faccaac"

  strings:
    $s1 = "} while (mw++ < op);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}