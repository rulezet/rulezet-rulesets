rule sig_20160527_0afccf37c153e3e15975dbdbf7063ef6 {
  meta:
    description = "datamaliciousorder - file 20160527_0afccf37c153e3e15975dbdbf7063ef6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21edc08ea10cd1e64bed4ac187ea53487d31bde59ed2edd111372124be684c90"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aRQvxlXL.length;i++)if(i%2==0)x.push(aRQvxlXL[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}