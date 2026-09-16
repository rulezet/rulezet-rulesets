rule sig_20160527_65da96d8cb59ab6e3933556c412b9f29 {
  meta:
    description = "datamaliciousorder - file 20160527_65da96d8cb59ab6e3933556c412b9f29.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "de2af26f98f08b3160a7cf2f794bbf95195e0616439fc9f61788ab61327547b0"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aK4DKuPT.length;i++)if(i%2==0)x.push(aK4DKuPT[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}