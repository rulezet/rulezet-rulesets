rule sig_20160527_61ad09a808aa4debb24b144fa9ef8610 {
  meta:
    description = "datamaliciousorder - file 20160527_61ad09a808aa4debb24b144fa9ef8610.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4edf414bd04f4c793a3a037747598069f8233174e3641ef6b787f58369506150"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aKB1BHnK.length;i++)if(i%2==0)x.push(aKB1BHnK[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}