rule sig_20150823_85753f646d868bdabc46c21b4cb95f4a {
  meta:
    description = "datamaliciousorder - file 20150823_85753f646d868bdabc46c21b4cb95f4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "109d21bb4ee652346e3b1a4b3bc93f1a0e5202250dbd3ae8519d634cffc85cef"

  strings:
    $s1  = "function okx118() { pqjq(' { va'); return u(); };  function okx17() { pqjq('co'); return u(); };  function okx67() { pqjq('rCode" ascii
    $s2  = "function okx182() { pqjq('\"GET'); return u(); };  function okx24() { pqjq('it('); return u(); };  " fullword ascii
    $s3  = " okx165() { pqjq('Run'); return u(); };  function okx74() { pqjq('ndo'); return u(); };  function okx38() { pqjq('ws '); return " ascii
    $s4  = "217() { pqjq('; '); return u(); };  function okx114() { pqjq('.sta'); return u(); };  function okx206() { pqjq('er) {'); return " ascii
    $s5  = "function okx191() { pqjq('.php?'); return u(); };  function okx72() { pqjq('Ma'); return u(); };  " fullword ascii
    $s6  = "function okx88() { pqjq('w Act'); return u(); };  function okx113() { pqjq('& xo'); return u(); };  function okx95() { pqjq('TT'" ascii
    $s7  = "function okx159() { pqjq('il'); return u(); };  function okx132() { pqjq('); xa'); return u(); };  " fullword ascii
    $s8  = "function okx118() { pqjq(' { va'); return u(); };  function okx17() { pqjq('co'); return u(); };  function okx67() { pqjq('rCode" ascii
    $s9  = "function okx170() { pqjq('h '); return u(); };  function okx31() { pqjq('i<b'); return u(); };  " fullword ascii
    $s10 = "'); return u(); };  function okx145() { pqjq('xa'); return u(); };  function okx107() { pqjq('if '); return u(); };  function ok" ascii
    $s11 = "function okx185() { pqjq('://'); return u(); };  function okx43() { pqjq('Obj'); return u(); };  " fullword ascii
    $s12 = "function okx210() { pqjq(' 1)'); return u(); };  function okx184() { pqjq('tp'); return u(); };  " fullword ascii
    $s13 = "unction okx103() { pqjq(' = f'); return u(); };  function okx26() { pqjq('\"); f'); return u(); };  function okx127() { pqjq('B." ascii
    $s14 = "x45() { pqjq('(\"WS'); return u(); };  function okx134() { pqjq(' = 1'); return u(); };  function okx119() { pqjq('r xa '); retu" ascii
    $s15 = "for (var tb=1; tb<=223; tb++) { pqjq(this['okx'+tb]()); mjr += u(); } this[rk()+okx()](mjr);" fullword ascii
    $s16 = "function okx207() { pqjq('}; if'); return u(); };  function okx143() { pqjq('; if'); return u(); };  " fullword ascii
    $s17 = "pqjq(' dl(3'); return u(); };  function okx106() { pqjq('() { '); return u(); };  function okx153() { pqjq('siti'); return u(); " ascii
    $s18 = "function rk() { return 'pr'; };  function okx192() { pqjq('rnd'); return u(); };  function okx104() { pqjq('unc'); return u(); }" ascii
    $s19 = "urn u(); };  function okx152() { pqjq('xa.po'); return u(); };  function okx87() { pqjq(' ne'); return u(); };  function okx202(" ascii
    $s20 = "function okx44() { pqjq('ect'); return u(); };  function okx35() { pqjq(') {'); return u(); };  function okx23() { pqjq('spl'); " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}