rule sig_20161024_7df5b3da838466b593261f75fc229b86 {
  meta:
    description = "datamaliciousorder - file 20161024_7df5b3da838466b593261f75fc229b86.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31602b8ec087d70c18d375eb8be9a43cd1d277a3e8a94bea1f7b9bcc2adb81dd"

  strings:
    $s1 = "} while (xk++ < dl0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}