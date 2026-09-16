rule sig_20160527_4ac17139541ff4d90705dacf46005cf3 {
  meta:
    description = "datamaliciousorder - file 20160527_4ac17139541ff4d90705dacf46005cf3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8cab770bc690baa8ce6d61abc165d027c3ce93e14124c3f3b1865b5c1f4f133"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aQDCXU.length;i++)if(i%2==0)x.push(aQDCXU[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}