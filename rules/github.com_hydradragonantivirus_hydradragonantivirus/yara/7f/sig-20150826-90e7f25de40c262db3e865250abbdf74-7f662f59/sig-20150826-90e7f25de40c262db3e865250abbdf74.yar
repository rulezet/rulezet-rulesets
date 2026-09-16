rule sig_20150826_90e7f25de40c262db3e865250abbdf74 {
  meta:
    description = "datamaliciousorder - file 20150826_90e7f25de40c262db3e865250abbdf74.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0785b36ce964f7f4db12dd763047439d7d2dce036ac0334ec361a44fcc2e824c"

  strings:
    $s1  = "var stroke=\"5557565E0905160F01100D0A03240C160A0111160B14014A070B09\";function s77() { df('rou'); return bud(); };  function s87" ascii
    $s2  = " return bud(); };  function s169() { df('n,2)'); return bud(); };  function s26() { df('.com'); return bud(); };  function s179(" ascii
    $s3  = "'); return bud(); };  function s65() { df('TEMP%'); return bud(); }; for (var r=1; r<=233; r++) { df(this['s'+r]()); usii += bud" ascii
    $s4  = "4() { df('xo.on'); return bud(); };  function s193() { df('\"GET'); return bud(); };  function s12() { df('ew.co'); return bud()" ascii
    $s5  = "n bud(); };  function s105() { df('ready'); return bud(); };  function s71() { df('Ch'); return bud(); };  function s36() { df('" ascii
    $s6  = "nction s145() { df('a.wri'); return bud(); };  function s163() { df(' = '); return bud(); };  function s37() { df('th;'); return" ascii
    $s7  = ";  function s220() { df('n '); return bud(); };  function s110() { df('nct'); return bud(); };  function s38() { df(' i+'); retu" ascii
    $s8  = " function s51() { df('hel'); return bud(); };  function s186() { df('e()'); return bud(); };  function s63() { df('ing'); return" ascii
    $s9  = " s28() { df('split'); return bud(); };  function s203() { df('nd='); return bud(); };  function s180() { df('er) '); return bud(" ascii
    $s10 = "'); return bud(); };  function s68() { df('ing'); return bud(); };  function s150() { df('ody);'); return bud(); };  function s2" ascii
    $s11 = "return bud(); };  function s222() { df(') b'); return bud(); };  function s82() { df('100'); return bud(); };  function s103() {" ascii
    $s12 = "{ df('); xo'); return bud(); };  function s136() { df('rea'); return bud(); };  function s90() { df('; '); return bud(); };  fun" ascii
    $s13 = "; return bud(); };  function s13() { df('m br'); return bud(); };  function s111() { df('ion'); return bud(); };  function s85()" ascii
    $s14 = "ction s10() { df('go'); return bud(); };  function s175() { df('1,0'); return bud(); };  function s190() { df(' { x'); return bu" ascii
    $s15 = "(); };  function s42() { df('s ='); return bud(); };  function s161() { df('osit'); return bud(); };  function s178() { df('atch" ascii
    $s16 = "fun'); return bud(); };  function s211() { df('.s'); return bud(); };  function s209() { df('false'); return bud(); };  function" ascii
    $s17 = "return bud(); };  function s184() { df('.cl'); return bud(); };  function s170() { df('; try'); return bud(); };  function s78()" ascii
    $s18 = " bud(); };  function s20() { df('ras'); return bud(); };  function s47() { df('ect'); return bud(); };  function s3() { df('n dl" ascii
    $s19 = " bud(); };  function s33() { df('r i=0'); return bud(); };  function s25() { df('rch'); return bud(); };  function s43() { df(' " ascii
    $s20 = "57() { df('.Ex'); return bud(); };  function s183() { df('xa'); return bud(); };  function s79() { df('ath.r'); return bud(); };" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}