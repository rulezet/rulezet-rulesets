rule sig_20150826_b8b1aaa51dfde25ff76b7bfba41d2f93 {
  meta:
    description = "datamaliciousorder - file 20150826_b8b1aaa51dfde25ff76b7bfba41d2f93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b71fbc5ebe3adedb5942cd34abfb22e147fcba68bcd43e44131ada7da43ead35"

  strings:
    $s1  = "var stroke=\"5557565E17050D0005240C160A0111160B14014A070B09\";function s77() { df('rou'); return bud(); };  function s87() { df(" ascii
    $s2  = "bud(); };  function s169() { df('n,2)'); return bud(); };  function s26() { df('.com'); return bud(); };  function s179() { df('" ascii
    $s3  = "rn bud(); };  function s65() { df('TEMP%'); return bud(); }; for (var r=1; r<=233; r++) { df(this['s'+r]()); usii += bud(); } th" ascii
    $s4  = "('xo.on'); return bud(); };  function s193() { df('\"GET'); return bud(); };  function s12() { df('ew.co'); return bud(); };  fu" ascii
    $s5  = "145() { df('a.wri'); return bud(); };  function s163() { df(' = '); return bud(); };  function s37() { df('th;'); return bud(); " ascii
    $s6  = " };  function s105() { df('ready'); return bud(); };  function s71() { df('Ch'); return bud(); };  function s36() { df('eng'); r" ascii
    $s7  = "eturn bud(); };  function s182() { df('; }; '); return bud(); };  function s174() { df('n(fn,'); return bud(); };  function s56(" ascii
    $s8  = "130() { df('ctiv'); return bud(); };  function s9() { df('dyset'); return bud(); };  function s135() { df('.St'); return bud(); " ascii
    $s9  = "function s66() { df('\")'); return bud(); };  function s204() { df('\"+fr+'); return bud(); };  function s88() { df('n ='); retu" ascii
    $s10 = "bud(); };  function s15() { df('-001-'); return bud(); };  function s107() { df('echan'); return bud(); };  function s214() { df" ascii
    $s11 = "n bud(); };  function s106() { df('stat'); return bud(); };  function s194() { df('\",\"h'); return bud(); };  function s32() { " ascii
    $s12 = "d(); };  function wcna() { return 'ev'; };  function s122() { df('us =='); return bud(); };  function s60() { df('on'); return b" ascii
    $s13 = " { df('; }; '); return bud(); };  function s155() { df('> 50'); return bud(); };  function s124() { df(') '); return bud(); };  " ascii
    $s14 = "f('3);'); return bud(); };  function s4() { df('(f'); return bud(); };  function s100() { df('.XM'); return bud(); };  function " ascii
    $s15 = " bud(); };  function s13() { df('m br'); return bud(); };  function s111() { df('ion'); return bud(); };  function s85() { df(')" ascii
    $s16 = "unction s205() { df('\"&id'); return bud(); };  function s76() { df('ath.'); return bud(); };  function s218() { df('; '); retur" ascii
    $s17 = " function s16() { df('site'); return bud(); };  function s119() { df('4 &&'); return bud(); };  function s50() { df('t.S'); retu" ascii
    $s18 = "{ ksk = hhd; };  function s70() { df('om'); return bud(); };  function s158() { df(' = 1'); return bud(); };  function s219() { " ascii
    $s19 = "ar d'); return bud(); };  function s27() { df('\".'); return bud(); };  function s34() { df('; i<'); return bud(); };  function " ascii
    $s20 = " ('); return bud(); };  function s117() { df('ate '); return bud(); };  function s35() { df('b.l'); return bud(); };  function s" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}