rule sig_20161024_d0f5ded4203ac5fd1e012d84faa5f46f {
  meta:
    description = "datamaliciousorder - file 20161024_d0f5ded4203ac5fd1e012d84faa5f46f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ad4a8db27fd8198cddc42d18c853e6c878842ec6c506766748a26cd07e773e1"

  strings:
    $s1 = "} while (wb++ < lr);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}