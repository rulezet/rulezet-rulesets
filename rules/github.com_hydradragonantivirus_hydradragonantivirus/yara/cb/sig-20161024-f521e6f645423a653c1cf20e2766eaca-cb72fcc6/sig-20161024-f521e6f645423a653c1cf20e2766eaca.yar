rule sig_20161024_f521e6f645423a653c1cf20e2766eaca {
  meta:
    description = "datamaliciousorder - file 20161024_f521e6f645423a653c1cf20e2766eaca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "119902d95188f1f9c67a2eaef4f50ffd038ddf501003f7613ac8852d79df96f7"

  strings:
    $s1 = "} while (cp++ < xq);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}