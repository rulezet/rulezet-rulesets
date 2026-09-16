rule sig_20161024_650c5080ddb7c04e57ac97aaa51a40cf {
  meta:
    description = "datamaliciousorder - file 20161024_650c5080ddb7c04e57ac97aaa51a40cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d035a5dce9c0c19eb12781b45b17ae9845c7099d164faf692313a3ad5ca46c77"

  strings:
    $s1 = "} while (rd++ < qk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}