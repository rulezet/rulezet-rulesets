rule sig_20161024_9b5ca024501497c1f28bd08c5e6897f4 {
  meta:
    description = "datamaliciousorder - file 20161024_9b5ca024501497c1f28bd08c5e6897f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b2fc3d2c4cb6c868981810f3cf52f3daf2da99acb12ab78af1446704cee3ac2"

  strings:
    $s1 = "} while (nh++ < ov);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}