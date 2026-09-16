rule sig_20160527_fd6d65bc7ee9593f2be59583b850b4f4 {
  meta:
    description = "datamaliciousorder - file 20160527_fd6d65bc7ee9593f2be59583b850b4f4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d130fa01e8530b03d75be0cf9b2abaae08f2ae2fc0111c93330ddddb85f5a5f"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a6tSph1y.length;i++)if(i%2==0)x.push(a6tSph1y[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}