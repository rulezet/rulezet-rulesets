rule sig_20161024_e7c5e5567875d8b1e9b74a203a519b4b {
  meta:
    description = "datamaliciousorder - file 20161024_e7c5e5567875d8b1e9b74a203a519b4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27974eca20e200775dfb7546a1c81488ece040a5f9f5fb84fb3bcef32e0aaab1"

  strings:
    $s1 = "} while (hf++ < my);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}