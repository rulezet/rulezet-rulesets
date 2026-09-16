rule sig_20161024_0986ce77242560308b625ae3307c568f {
  meta:
    description = "datamaliciousorder - file 20161024_0986ce77242560308b625ae3307c568f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5181ff709876a332a2a0dee01b02ecf06f623a130c99d7bf16ead88c8b618a0"

  strings:
    $s1 = "} while (os++ < yw);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}