rule sig_20160517_23bdd445046ed94bd1d4f8fba6a29849 {
  meta:
    description = "datamaliciousorder - file 20160517_23bdd445046ed94bd1d4f8fba6a29849.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68d96fdfa948abb3ff95a282180eb72af475923fe5d8da6d95ffa0e78d4dec5a"

  strings:
    $s1 = "var fzur='vdawbgavgj4hrf1rbr etu4vggbb2b3wjvkd4umisskmv3dzps2zbdvwh2llrxrr3tomfcstrcngxg=ercby\\'gq1avttvdehcwa4jcnigm43ianqqlfe" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}