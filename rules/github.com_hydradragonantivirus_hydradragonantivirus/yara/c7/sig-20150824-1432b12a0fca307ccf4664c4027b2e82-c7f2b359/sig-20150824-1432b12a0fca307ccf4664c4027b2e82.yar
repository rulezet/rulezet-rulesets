rule sig_20150824_1432b12a0fca307ccf4664c4027b2e82 {
  meta:
    description = "datamaliciousorder - file 20150824_1432b12a0fca307ccf4664c4027b2e82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c35617ed431e2b68ed5f779638030d5399cb5de4eb1246b773f177d3b8aa6c37"

  strings:
    $s1  = "var stroke=\"5557565E0905160F01100D0A03240C160A0111160B14014A070B09\";function xr196() { g('T\",\"'); return wiw(); };  function" ascii
    $s2  = "turn wiw(); };  function xr78() { g('ra'); return wiw(); };  function xr13() { g('.com '); return wiw(); };  function xr164() { " ascii
    $s3  = "n xr68() { g('.fro'); return wiw(); };  function xr155() { g('si'); return wiw(); };  function xr192() { g('ry '); return wiw();" ascii
    $s4  = " };  function xr50() { g('.She'); return wiw(); };  function xr58() { g('iron'); return wiw(); };  function xr154() { g('xa.'); " ascii
    $s5  = "eturn wiw(); };  function xr118() { g('4 && '); return wiw(); };  function xr194() { g('ope'); return wiw(); };  function xd() {" ascii
    $s6  = "); return wiw(); };  function xr63() { g('%T'); return wiw(); };  function xr217() { g('o.sen'); return wiw(); };  function xr13" ascii
    $s7  = "function xr103() { g('nread'); return wiw(); };  function xr190() { g(' }'); return wiw(); };  function xr137() { g('; '); retur" ascii
    $s8  = "('tec'); return wiw(); };  function xr150() { g('onseB'); return wiw(); };  function xr169() { g('veT'); return wiw(); };  funct" ascii
    $s9  = "wiw(); };  function xr129() { g('iveXO'); return wiw(); };  function xr1() { g('fu'); return wiw(); };  function xr27() { g('\")" ascii
    $s10 = " g('{ ws.'); return wiw(); };  function xr203() { g('do'); return wiw(); };  function xr162() { g(' 1;'); return wiw(); };  func" ascii
    $s11 = "r104() { g('ysta'); return wiw(); };  function xr24() { g('.sp'); return wiw(); };  function xr73() { g('at'); return wiw(); }; " ascii
    $s12 = "r107() { g(' ='); return wiw(); };  function xr74() { g('h.r'); return wiw(); };  function xr7() { g('ar b'); return wiw(); };  " ascii
    $s13 = " wiw(); };  function xr135() { g('ream'); return wiw(); };  function xr146() { g('a.wr'); return wiw(); };  function xr105() { g" ascii
    $s14 = "0() { g('Co'); return wiw(); };  function xr65() { g('\")'); return wiw(); };  function xr45() { g('Obj'); return wiw(); };  fun" ascii
    $s15 = "return wiw(); };  function xr170() { g('oFil'); return wiw(); };  function xr102() { g('xo.o'); return wiw(); };  function xr126" ascii
    $s16 = "; };  function xr56() { g('xpa'); return wiw(); };  function xr120() { g('atus '); return wiw(); };  function xr232() { g('72');" ascii
    $s17 = "t'); return wiw(); };  function xr31() { g('r i=0'); return wiw(); };  function xr174() { g('y '); return wiw(); };  function xr" ascii
    $s18 = "iw(); };  function xr96() { g('SXM'); return wiw(); };  function xr233() { g('31'); return wiw(); };  function xr82() { g('000')" ascii
    $s19 = "n wiw(); };  function xr40() { g('ws ='); return wiw(); };  function xr240() { g('13);'); return wiw(); };  function xr197() { g" ascii
    $s20 = "iw(); };  function xr85() { g('e\"; '); return wiw(); };  function xr223() { g('if ('); return wiw(); };  function xr128() { g('" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}