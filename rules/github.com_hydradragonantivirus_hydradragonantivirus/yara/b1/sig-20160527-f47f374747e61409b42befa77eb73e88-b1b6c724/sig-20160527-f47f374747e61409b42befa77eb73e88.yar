rule sig_20160527_f47f374747e61409b42befa77eb73e88 {
  meta:
    description = "datamaliciousorder - file 20160527_f47f374747e61409b42befa77eb73e88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8559d3f046e7a9a4642d5833ce240a4c7d1290f0600977f450df330c19d37244"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aW9qk1q14RB.length;i++)if(i%2==0)x.push(aW9qk1q14RB[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}