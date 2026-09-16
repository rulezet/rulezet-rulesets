rule sig_20161024_b74a6baa9bc7c4d49a69b0a0738ebca9 {
  meta:
    description = "datamaliciousorder - file 20161024_b74a6baa9bc7c4d49a69b0a0738ebca9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e028a066c619e47365e92340ee07d1c45425e80193114b264155012c207d506"

  strings:
    $s1 = "} while (pr++ < me);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}