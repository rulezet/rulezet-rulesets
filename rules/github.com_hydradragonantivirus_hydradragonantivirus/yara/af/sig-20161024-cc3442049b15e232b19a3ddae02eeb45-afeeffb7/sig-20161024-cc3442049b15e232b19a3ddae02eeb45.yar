rule sig_20161024_cc3442049b15e232b19a3ddae02eeb45 {
  meta:
    description = "datamaliciousorder - file 20161024_cc3442049b15e232b19a3ddae02eeb45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f42e42ef67bb59d62144ba87e542efffd148990af022748b5e069871b42f937"

  strings:
    $s1 = "} while (jn++ < nh);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}