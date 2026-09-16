rule sig_20161024_adb8a82fd2e8b304fbef5fc34df0940f {
  meta:
    description = "datamaliciousorder - file 20161024_adb8a82fd2e8b304fbef5fc34df0940f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cca46f04860debfae88ae9716abb8df867241fff68b1eda3e56c0acefd3af0f"

  strings:
    $s1 = "} while (nk0++ < jm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}