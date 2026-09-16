rule sig_20160527_94f59710cb80c56a19945c774a709717 {
  meta:
    description = "datamaliciousorder - file 20160527_94f59710cb80c56a19945c774a709717.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09f27d06f486fb2fbea8c00f895e3e637005de7b544892935f38fd0e32ced842"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aD9PR0Is.length;i++)if(i%2==0)x.push(aD9PR0Is[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}