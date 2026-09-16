rule sig_20160527_f6dcd01e00ceda939f1af3fd3d009529 {
  meta:
    description = "datamaliciousorder - file 20160527_f6dcd01e00ceda939f1af3fd3d009529.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d75ba738e094106bac807bfcd6df511b796320f66417b628a0b5844e9e65901b"

  strings:
    $s1 = "    x = new Array(); for (i=0;i<a97qPRuIw.length;i++)if(i%2==0)x.push(a97qPRuIw[\"charAt\"](i));" fullword ascii

  condition:
    uint16(0) == 0x2a2f and
    all of them
}