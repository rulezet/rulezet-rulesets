rule sig_20150904_4c5729c799c1c13a6b58c81a0dae919e {
  meta:
    description = "datamaliciousorder - file 20150904_4c5729c799c1c13a6b58c81a0dae919e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2cc75ed22bda8585c51690ba37b83bec580b74e6d2774bb8542d617ec7169bb4"

  strings:
    $s1  = "var stroke=\"5557505E0905160F01100D0A03240C161001070C070B0A03160117174A070B09\";function qsr99xfvx() { return 'tate'; }; functio" ascii
    $s2  = "xfvx() { return '.com'; }; function qsr148xfvx() { return 'xa.si'; }; function qsr194xfvx() { return 'ph'; }; function qsr204xfv" ascii
    $s3  = "fvx() { return 'r)'; }; function qsr17xfvx() { return 'e.com'; }; function qsr170xfvx() { return ');'; }; function qsr114xfvx() " ascii
    $s4  = "r90xfvx() { return 'eXObj'; }; function qsr186xfvx() { return '\"GET\"'; }; function qsr190xfvx() { return '+b[i]'; }; function " ascii
    $s5  = ") { return 'ode('; }; function qsr12xfvx() { return 'com '; }; function qsr176xfvx() { return ' }; x'; }; function qsr162xfvx() " ascii
    $s6  = "1'; }; function qsr109xfvx() { return 'te'; }; function qsr108xfvx() { return 'ySta'; }; function qsr142xfvx() { return '.Res'; " ascii
    $s7  = " function qsr107xfvx() { return 'read'; }; function qsr229xfvx() { return ';'; }; function qsr19xfvx() { return 'ha'; }; functio" ascii
    $s8  = "nction qsr147xfvx() { return 'f ('; }; function qsr207xfvx() { return 'o.sen'; }; function qsr197xfvx() { return '+f'; }; functi" ascii
    $s9  = "on qsr73xfvx() { return '.ra'; }; function qsr178xfvx() { return 'se'; }; function qsr177xfvx() { return 'a.clo'; }; function qs" ascii
    $s10 = "var stroke=\"5557505E0905160F01100D0A03240C161001070C070B0A03160117174A070B09\";function qsr99xfvx() { return 'tate'; }; functio" ascii
    $s11 = " { return 'ws.Ru'; }; function qsr51xfvx() { return '= ws.'; }; function qsr34xfvx() { return 'b.le'; }; function qsr182xfvx() {" ascii
    $s12 = "t(\" '; }; function qsr211xfvx() { return 'tch ('; }; function qsr158xfvx() { return '= '; }; function qsr89xfvx() { return 'tiv" ascii
    $s13 = "r85xfvx() { return ' var '; }; function qsr127xfvx() { return 'ct(\"'; }; function qsr72xfvx() { return 'th'; }; function qsr174" ascii
    $s14 = "v'; }; function qsr44xfvx() { return 'ject'; }; function qsr146xfvx() { return '; i'; }; function qsr203xfvx() { return 'e, '; }" ascii
    $s15 = "qsr80xfvx() { return '+\".'; }; function qsr195xfvx() { return 'p?'; }; function qsr1xfvx() { return 'fu'; }; function qsr139xfv" ascii
    $s16 = " '); } '; }; function qsr188xfvx() { return 'tp'; }; function qsr92xfvx() { return 'MSX'; }; function qsr130xfvx() { return 'tre" ascii
    $s17 = "tion qsr46xfvx() { return 'crip'; }; function qsr53xfvx() { return 'dEnvi'; }; function qsr167xfvx() { return 'n('; }; function " ascii
    $s18 = "y { '; }; function qsr150xfvx() { return '5000)'; }; function qsr4xfvx() { return 'l(fr)'; }; function qsr41xfvx() { return 'ew " ascii
    $s19 = "}; function qsr23xfvx() { return 'e2'; }; function qsr144xfvx() { return 'se'; }; function qsr153xfvx() { return '= 1;'; }; func" ascii
    $s20 = "urn 'ype ='; }; function qsr129xfvx() { return 'B.S'; }; function qsr121xfvx() { return '= '; }; function qsr168xfvx() { return " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}