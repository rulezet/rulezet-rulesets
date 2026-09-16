rule sig_20161024_ee5deb1ee7855a832645be253bcd40e6 {
  meta:
    description = "datamaliciousorder - file 20161024_ee5deb1ee7855a832645be253bcd40e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "906f03d91317a1f5916d2aa089a0f2ae64666cc0a3106ca44d4ed05def4ff0cc"

  strings:
    $s1 = "} while (xr++ < rb);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}