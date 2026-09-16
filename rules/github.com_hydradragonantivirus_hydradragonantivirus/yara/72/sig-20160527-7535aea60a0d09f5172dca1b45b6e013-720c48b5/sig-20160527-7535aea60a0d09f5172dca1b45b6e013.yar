rule sig_20160527_7535aea60a0d09f5172dca1b45b6e013 {
  meta:
    description = "datamaliciousorder - file 20160527_7535aea60a0d09f5172dca1b45b6e013.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0cc869ae0eefd450fbf6e8f05f2475d1033026e6f57914f42b6c86d804c2394"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<anwdRvC.length;i++)if(i%2==0)x.push(anwdRvC[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}