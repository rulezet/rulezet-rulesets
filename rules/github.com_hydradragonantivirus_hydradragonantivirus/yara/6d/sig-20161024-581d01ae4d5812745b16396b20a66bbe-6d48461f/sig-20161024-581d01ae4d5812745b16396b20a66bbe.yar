rule sig_20161024_581d01ae4d5812745b16396b20a66bbe {
  meta:
    description = "datamaliciousorder - file 20161024_581d01ae4d5812745b16396b20a66bbe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b7f588dbb8d919e863da06a83a09be4c07854fc701474d6009085f6a93be5ec"

  strings:
    $s1 = "} while (gq++ < jp0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}