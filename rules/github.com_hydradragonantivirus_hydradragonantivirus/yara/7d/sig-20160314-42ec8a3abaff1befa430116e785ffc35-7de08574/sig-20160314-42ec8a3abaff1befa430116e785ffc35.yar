rule sig_20160314_42ec8a3abaff1befa430116e785ffc35 {
  meta:
    description = "datamaliciousorder - file 20160314_42ec8a3abaff1befa430116e785ffc35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0cf41d31a9667c47f9a1bfbf93c910a290f1aafafef3755cbd5216729bcddfc0"

  strings:
    $s1 = "EFgMrttVuQrvB.open(zlAiegdqMR + iJVEPLHzgaBl, TgpQLwdigbA + ktHzgKFxbGmWfqE + FLUDJkzMuKHwFyd + kfJxYYAfHhRzUKS + VTutiKHwK + ie" ascii
    $s2 = "while (EFgMrttVuQrvB.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "return StSORth + wWTR + hgbMyfqsMCWKsZ + LHDaVlbfCyaCgWk + utNvYCNlOPpEe + wehqXXflHt + wcmxj" fullword ascii
    $s4 = "gpaWHwAycd + rVH + IUTqHuli + hJpdooDgxt + wkst + ZZT + xbMqAlwOcEnDE + TProMapPlwNl, false);" fullword ascii
    $s5 = "var uIeJjYGK = new Date();" fullword ascii
    $s6 = "function UnHqOoFPm(fname)" fullword ascii
    $s7 = "function zDwlyDWVElR(n)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}