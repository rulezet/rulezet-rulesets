rule sig_20160527_a733ad49d2e9c7b1c90f558c50870f1b {
  meta:
    description = "datamaliciousorder - file 20160527_a733ad49d2e9c7b1c90f558c50870f1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb9163fd4c185933c9eba21f020252217bd29baff75968e124b80a1405301594"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<aoapoO1.length;i++)if(i%2==0)x.push(aoapoO1[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}