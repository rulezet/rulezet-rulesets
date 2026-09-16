rule sig_20161024_2546a651f4f4edd8bcb3754b8530dcc3 {
  meta:
    description = "datamaliciousorder - file 20161024_2546a651f4f4edd8bcb3754b8530dcc3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "337179f71edfd5b551720bf8fc609dbabd7305f6a374afee32038a9a584fe6c7"

  strings:
    $s1 = "} while (nv++ < le);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}