rule sig_20161024_4802ec7fdf1967a721cfaefeea50bacf {
  meta:
    description = "datamaliciousorder - file 20161024_4802ec7fdf1967a721cfaefeea50bacf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2adf81c8549a47270d591eb369fd14c0062c5bcc7e183fa07a0c7590ec60beac"

  strings:
    $s1 = "} while (rt++ < iz);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}