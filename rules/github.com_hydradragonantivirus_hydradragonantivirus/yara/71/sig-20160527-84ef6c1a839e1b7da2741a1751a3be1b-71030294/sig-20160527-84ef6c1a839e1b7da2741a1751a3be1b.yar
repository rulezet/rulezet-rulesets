rule sig_20160527_84ef6c1a839e1b7da2741a1751a3be1b {
  meta:
    description = "datamaliciousorder - file 20160527_84ef6c1a839e1b7da2741a1751a3be1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c2b5793cb858633faa894e433e838352d9c3852e3189b0da045718f8344e102"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a8IHHzR8.length;i++)if(i%2==0)x.push(a8IHHzR8[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}