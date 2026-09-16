rule sig_20161024_42f04cd82bea8cf1236036c66cfc8452 {
  meta:
    description = "datamaliciousorder - file 20161024_42f04cd82bea8cf1236036c66cfc8452.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c48a300dd24eaa5300fc57cadd3788925aae4ab799963d411d8c18fc45b20e71"

  strings:
    $s1 = "} while (ew++ < yt);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}