rule sig_20150822_a6d09f5e5d36e6f0265facd1019f5523 {
  meta:
    description = "datamaliciousorder - file 20150822_a6d09f5e5d36e6f0265facd1019f5523.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d824cb3dffd0f67452c84d56ded2f57b4c29e81eae76561a505e71110785be4"

  strings:
    $s1  = "j108() { vh('ha'); return vl(); };  function uj62() { vh('TEMP%'); return vl(); };  function uj44() { vh('t(\"'); return vl(); }" ascii
    $s2  = "function uj27() { vh('for ('); return vl(); };  function uj7() { vh(') '); return vl(); };  function uj111() { vh(' f'); return " ascii
    $s3  = "{ vh('var'); return vl(); };  function uj128() { vh('00)'); return vl(); };  function uj189() { vh('.clo'); return vl(); };  fun" ascii
    $s4  = " uj21() { vh('com\"'); return vl(); };  function uj31() { vh('i<b'); return vl(); };  function uj209() { vh('hp?rn'); return vl(" ascii
    $s5  = " };  function uj183() { vh('atch '); return vl(); };  function uj158() { vh('.siz'); return vl(); };  function uj113() { vh('cti" ascii
    $s6  = "; };  function uj66() { vh('om'); return vl(); };  function uj53() { vh('s.Exp'); return vl(); };  function uj26() { vh('); '); " ascii
    $s7  = ".len'); return vl(); };  function uj17() { vh('ar.c'); return vl(); };  function uj166() { vh('osit'); return vl(); };  function" ascii
    $s8  = "eturn vl(); };  function uj146() { vh('xa.t'); return vl(); };  function uj112() { vh('un'); return vl(); };  function uj222() {" ascii
    $s9  = " dn ='); return vl(); };  function uj38() { vh('ws = '); return vl(); };  function uj28() { vh('var '); return vl(); };  functio" ascii
    $s10 = "for (var s=1; s<=244; s++) { vh(this['uj'+s]()); pdcr += vl(); } " fullword ascii
    $s11 = " return vl(); };  function uj34() { vh('; '); return vl(); };  function uj187() { vh('; '); return vl(); };  function uj171() { " ascii
    $s12 = "(); };  function uj204() { vh('+b['); return vl(); };  function uj84() { vh(' dn '); return vl(); };  function uj4() { vh('n d')" ascii
    $s13 = "uj211() { vh('+fr+'); return vl(); };  function uj185() { vh(' {'); return vl(); };  function uj61() { vh('(\"%'); return vl(); " ascii
    $s14 = " function uj238() { vh('41'); return vl(); };  function uj71() { vh('+Math'); return vl(); };  function uj104() { vh('onre'); re" ascii
    $s15 = "j230() { vh('= '); return vl(); };  function uj195() { vh('{ xo'); return vl(); };  function uj240() { vh('dl(8'); return vl(); " ascii
    $s16 = "vl(); };  function uj121() { vh('te '); return vl(); };  function uj218() { vh('xo.s'); return vl(); };  function uj162() { vh('" ascii
    $s17 = "  function uj64() { vh('rin'); return vl(); };  function uj144() { vh('open('); return vl(); };  function uj25() { vh('(\" \"');" ascii
    $s18 = " vh('} '); return vl(); };  function uj77() { vh('()*10'); return vl(); };  function uj216() { vh(' fals'); return vl(); };  fun" ascii
    $s19 = "ction uj203() { vh('//\"'); return vl(); };  function uj23() { vh('pl'); return vl(); };  function uj41() { vh('tive'); return v" ascii
    $s20 = "this[e()+uj()](pdcr); " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}