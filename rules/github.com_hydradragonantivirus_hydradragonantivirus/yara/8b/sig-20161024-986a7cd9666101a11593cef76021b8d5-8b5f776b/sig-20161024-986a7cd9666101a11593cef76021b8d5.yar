rule sig_20161024_986a7cd9666101a11593cef76021b8d5 {
  meta:
    description = "datamaliciousorder - file 20161024_986a7cd9666101a11593cef76021b8d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33676a9e696c0b0185a8b345a66b5b7ff08144961c75e43db12fb7f1d8385f7c"

  strings:
    $s1 = "} while (re++ < oe0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}