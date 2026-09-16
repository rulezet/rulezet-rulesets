rule sig_20150820_525fa73a3cae382500ef362f5308dd00 {
  meta:
    description = "datamaliciousorder - file 20150820_525fa73a3cae382500ef362f5308dd00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c85db11ba5d639e24e70bf02aacfe27d27091bd09f000cca80bfc797b80cdca6"

  strings:
    $s1  = "var stroke=\"5557545E0D0A020B24060108130B0B000A1D4A070B09\";function l43() { nz('WScri'); return nc(); };  function l201() { nz(" ascii
    $s2  = "nction l112() { nz(' =='); return nc(); };  function l197() { nz('str'); return nc(); };  function l94() { nz('HTTP'); return nc" ascii
    $s3  = "'o.rea'); return nc(); };  function l44() { nz('pt.Sh'); return nc(); };  function l155() { nz('siti'); return nc(); };  functio" ascii
    $s4  = "nction l12() { nz('com l'); return nc(); };  function l87() { nz('new A'); return nc(); };  function l118() { nz('20'); return n" ascii
    $s5  = " function l152() { nz(' = 1;'); return nc(); };  function l93() { nz('2.XML'); return nc(); };  function l117() { nz(' == '); re" ascii
    $s6  = "nz('onr'); return nc(); };  function l224() { nz('l(158'); return nc(); };  function l192() { nz('.php'); return nc(); };  funct" ascii
    $s7  = "unction l177() { nz(');'); return nc(); };  function l45() { nz('el'); return nc(); };  function l186() { nz('tt'); return nc();" ascii
    $s8  = " };  function l150() { nz('00) '); return nc(); };  var n = ''; var rpui = '';  function l137() { nz('; xa'); return nc(); };  f" ascii
    $s9  = "() { nz('(xa.'); return nc(); };  function l160() { nz('veTo'); return nc(); };  function l21() { nz('.co'); return nc(); };  fu" ascii
    $s10 = "); };  function l127() { nz('ct(\"A'); return nc(); };  function l161() { nz('File('); return nc(); };  function l110() { nz('dy" ascii
    $s11 = "); };  function nc() { return rpui; };  function l1() { nz('fu'); return nc(); };  function l83() { nz('0; '); return nc(); };  " ascii
    $s12 = "'ra'); return nc(); };  function l156() { nz('on '); return nc(); };  function l24() { nz('t(\" '); return nc(); };  function l2" ascii
    $s13 = " function l210() { nz('}; if'); return nc(); };  function l218() { nz('54'); return nc(); };  function l154() { nz('a.po'); retu" ascii
    $s14 = "function l133() { nz('en('); return nc(); };  function l65() { nz('de(92'); return nc(); };  function l101() { nz('tech'); retur" ascii
    $s15 = " function l203() { nz('o.se'); return nc(); };  function l13() { nz('ater'); return nc(); };  function l116() { nz('atus'); retu" ascii
    $s16 = " { nz('b.le'); return nc(); };  function l134() { nz('); xa'); return nc(); };  function l46() { nz('l\")'); return nc(); };  fu" ascii
    $s17 = "rn nc(); };  function l67() { nz('ath.'); return nc(); };  function l95() { nz('\")'); return nc(); }; for (var uud=1; uud<=225;" ascii
    $s18 = "turn nc(); };  function l92() { nz('MSXML'); return nc(); };  function l198() { nz('ok'); return nc(); };  function l158() { nz(" ascii
    $s19 = "rn nc(); };  function l168() { nz('n,1'); return nc(); };  function l129() { nz('DB.St'); return nc(); };  function l109() { nz(" ascii
    $s20 = "turn nc(); };  function l104() { nz('ncti'); return nc(); };  function l37() { nz('= n'); return nc(); };  function l14() { nz('" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}