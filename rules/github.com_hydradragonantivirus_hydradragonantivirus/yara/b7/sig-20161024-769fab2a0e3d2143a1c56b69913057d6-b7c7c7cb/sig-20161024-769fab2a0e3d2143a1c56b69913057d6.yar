rule sig_20161024_769fab2a0e3d2143a1c56b69913057d6 {
  meta:
    description = "datamaliciousorder - file 20161024_769fab2a0e3d2143a1c56b69913057d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0968ed79e814531ec7b105c26c088e27c79ac5bee828af1cf8b870d7c0fb95cb"

  strings:
    $s1 = "} while (jm++ < ac);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}