rule sig_20161024_9ed8a0227a166e6b52ed159af6de4b8a {
  meta:
    description = "datamaliciousorder - file 20161024_9ed8a0227a166e6b52ed159af6de4b8a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c18f9692c10ae59048877dbe18a9f1b15a159c83823872203d5a491d8f1f56d"

  strings:
    $s1 = "} while (nx0++ < lc);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}