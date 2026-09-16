rule sig_20150821_85438a1626f3742cf847d8b79bfd002f {
  meta:
    description = "datamaliciousorder - file 20150821_85438a1626f3742cf847d8b79bfd002f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5eb4605b82181edf7842d23de64460891bf09f63c2996a675b69db1fa4ba161"

  strings:
    $s1  = "var stroke=\"5557545E0C160A240C160A0111160B14014A070B09\";function ja76() { z('; '); return ea(); };  function ja188() { z('+\"/" ascii
    $s2  = " { z('tive'); return ea(); };  function ja182() { z('GET'); return ea(); };  function ja69() { z('000)+'); return ea(); };  func" ascii
    $s3  = "); return ea(); };  function ja45() { z('s.Exp'); return ea(); };  function ja122() { z('je'); return ea(); };  function ja99() " ascii
    $s4  = "z('ngth;'); return ea(); };  function ja89() { z('LHTTP'); return ea(); };  function ja5() { z(' { va'); return ea(); };  functi" ascii
    $s5  = "n ea(); };  var lx = ''; var el = '';  function ja40() { z('.She'); return ea(); };  function ja129() { z('n(); '); return ea();" ascii
    $s6  = "n ea(); };  function ja192() { z('.php?'); return ea(); };  function ja219() { z('41); '); return ea(); };  function ja8() { z('" ascii
    $s7  = "  function ja83() { z('Ob'); return ea(); };  function ja167() { z(' }'); return ea(); };  function ja180() { z('o.ope'); return" ascii
    $s8  = "{ z('on('); return ea(); };  function ja158() { z('(f'); return ea(); };  function ja203() { z('.sen'); return ea(); };  functio" ascii
    $s9  = "ja127() { z('; x'); return ea(); };  function ja110() { z('.sta'); return ea(); };  function ja171() { z(') {}'); return ea(); }" ascii
    $s10 = " function ja39() { z('cript'); return ea(); };  function ja144() { z('a.siz'); return ea(); };  function ja202() { z(' xo'); ret" ascii
    $s11 = "a211() { z('(dn'); return ea(); };  function ja104() { z('.rea'); return ea(); };  function ja131() { z('ype '); return ea(); };" ascii
    $s12 = "() { z('nment'); return ea(); };  function ja201() { z('lse);'); return ea(); };  function ja128() { z('a.ope'); return ea(); };" ascii
    $s13 = " return ea(); };  function ja143() { z('f (x'); return ea(); };  function ja72() { z('\"; '); return ea(); };  function ja29() {" ascii
    $s14 = "on ja214() { z('bre'); return ea(); };  function ja91() { z(' xo.o'); return ea(); };  function ja116() { z('{ '); return ea(); " ascii
    $s15 = "nction ja215() { z('ak; '); return ea(); };  function ja223() { z('; '); return ea(); };  function ja207() { z('ch (e'); return " ascii
    $s16 = "function ja177() { z(' }; }'); return ea(); };  function ja44() { z(' = w'); return ea(); };  function ja24() { z('; fo'); retur" ascii
    $s17 = " };  function ja33() { z(' = n'); return ea(); };  function ja34() { z('ew Ac'); return ea(); };  function ja81() { z('ct'); ret" ascii
    $s18 = "0() { z('a.'); return ea(); };  function ja13() { z('stry'); return ea(); };  function ja79() { z('= n'); return ea(); };  funct" ascii
    $s19 = "('1,0);'); return ea(); };  function ja152() { z('ion '); return ea(); };  function ja18() { z('tthew'); return ea(); };  functi" ascii
    $s20 = " function ja73() { z('va'); return ea(); };  function ja183() { z('\",\"h'); return ea(); };  function ja205() { z(' } '); retur" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}