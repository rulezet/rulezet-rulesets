rule sig_20150824_16460117bc3e3a27c0ad13805ec01a0b {
  meta:
    description = "datamaliciousorder - file 20150824_16460117bc3e3a27c0ad13805ec01a0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38ada9f6d21d2583df652c5969127115f2593eff86d0c9114bf83c08b33a9f47"

  strings:
    $s1  = "var stroke=\"5557565E17050D0005240C160A0111160B14014A070B09\";function xr196() { g('T\",\"'); return wiw(); };  function xr70() " ascii
    $s2  = "(); };  function xr78() { g('ra'); return wiw(); };  function xr13() { g('.com '); return wiw(); };  function xr164() { g('po');" ascii
    $s3  = "n wiw(); };  function xr63() { g('%T'); return wiw(); };  function xr217() { g('o.sen'); return wiw(); };  function xr132() { g(" ascii
    $s4  = "w(); };  function xr118() { g('4 && '); return wiw(); };  function xr194() { g('ope'); return wiw(); };  function xd() { return " ascii
    $s5  = "ction xr50() { g('.She'); return wiw(); };  function xr58() { g('iron'); return wiw(); };  function xr154() { g('xa.'); return w" ascii
    $s6  = " { g('.fro'); return wiw(); };  function xr155() { g('si'); return wiw(); };  function xr192() { g('ry '); return wiw(); };  fun" ascii
    $s7  = " xr103() { g('nread'); return wiw(); };  function xr190() { g(' }'); return wiw(); };  function xr137() { g('; '); return wiw();" ascii
    $s8  = "urn wiw(); };  function xr142() { g('.t'); return wiw(); };  function xr99() { g('TP'); return wiw(); };  function xr84() { g('" ascii
    $s9  = "'+St'); return wiw(); };  function xr182() { g(' (e'); return wiw(); };  function xr160() { g(' dn'); return wiw(); };  function" ascii
    $s10 = "};  function xr135() { g('ream'); return wiw(); };  function xr146() { g('a.wr'); return wiw(); };  function xr105() { g('tec');" ascii
    $s11 = "'\"ADO'); return wiw(); };  function xr119() { g('xo.st'); return wiw(); };  function xr237() { g(');'); return wiw(); };  funct" ascii
    $s12 = "'); return wiw(); };  function xr205() { g('nt.ph'); return wiw(); };  function xr18() { g('om '); return wiw(); };  function xr" ascii
    $s13 = "8() { g('p:/'); return wiw(); };  function xr212() { g('=\"+s'); return wiw(); };  function xr228() { g('reak;'); return wiw(); " ascii
    $s14 = "n wiw(); };  function xr20() { g('o-a'); return wiw(); };  function xr127() { g('ew A'); return wiw(); };  function xr163() { g(" ascii
    $s15 = "ction xr204() { g('cume'); return wiw(); };  function xr33() { g('.l'); return wiw(); };  function xr76() { g('d(M'); return wiw" ascii
    $s16 = "  function xr133() { g('DB.'); return wiw(); };  function xr61() { g('rings'); return wiw(); };  function xr80() { g(')*100'); r" ascii
    $s17 = "; };  function xr167() { g('0; x'); return wiw(); };  function xr81() { g('00'); return wiw(); };  function xr144() { g('= '); r" ascii
    $s18 = "var stroke=\"5557565E17050D0005240C160A0111160B14014A070B09\";function xr196() { g('T\",\"'); return wiw(); };  function xr70() " ascii
    $s19 = "iw(); };  function xr113() { g(' (xo.'); return wiw(); };  function xr215() { g('lse);'); return wiw(); };  function xr66() { g(" ascii
    $s20 = "(); };  function xr28() { g('; fo'); return wiw(); };  function xr26() { g('(\" '); return wiw(); };  function xr109() { g('ct')" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}