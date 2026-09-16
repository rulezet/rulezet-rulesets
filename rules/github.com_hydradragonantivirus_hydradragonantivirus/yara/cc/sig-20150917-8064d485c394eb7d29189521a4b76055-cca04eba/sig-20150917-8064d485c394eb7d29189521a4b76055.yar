rule sig_20150917_8064d485c394eb7d29189521a4b76055 {
  meta:
    description = "datamaliciousorder - file 20150917_8064d485c394eb7d29189521a4b76055.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30b544e475151c651f6ae4efbbb889f57af93a8848b20362193ef19929e8d5cb"

  strings:
    $s1  = "var str=\"5550575E060B0300050A240C160A0111160B14014A070B09\";function ixo464340() { return 'TEMP'; }; /* var n=ixo200709(); */ /" ascii
    $s2  = "*/ function ixo851290() { return 'n() {'; }; /* var n=ixo970135(); */ function ixo177997() { return '.com\"'; }; function ixo141" ascii
    $s3  = "var str=\"5550575E060B0300050A240C160A0111160B14014A070B09\";function ixo464340() { return 'TEMP'; }; /* var n=ixo200709(); */ /" ascii
    $s4  = "* var n=ixo530383(); */ /* var n=ixo730781(); */ /* var n=ixo406617(); */ function ixo990592() { return ' xa'; }; /* var n=ixo83" ascii
    $s5  = "* var n=ixo332532(); */ function ixo518513() { return 'ode('; }; function ixo441123() { return 'tS'; }; function ixo1772231() { " ascii
    $s6  = ") { return 'atus '; }; function ixo472079() { return '%\")'; }; function ixo77390() { return 'comm'; }; /* var n=ixo306322(); */" ascii
    $s7  = "; /* var n=ixo294920(); */ function ixo1044765() { return 'B.Str'; }; /* var n=ixo975779(); */ /* var n=ixo115501(); */ /* var n" ascii
    $s8  = "turn 'http'; }; /* var n=ixo231906(); */ function ixo696510() { return ' = n'; }; /* var n=ixo522362(); */ function ixo1153111()" ascii
    $s9  = "() { return 'lanka'; }; /* var n=ixo815369(); */ function ixo278604() { return ' ws ='; }; function ixo131563() { return 'e2.'; " ascii
    $s10 = "616(); */ /* var n=ixo205609(); */ /* var n=ixo290611(); */ /* var n=ixo960988(); */ function ixo588164() { return 'do'; }; func" ascii
    $s11 = " }; function ixo549469() { return 'un'; }; /* var n=ixo236583(); */ function ixo959636() { return ' 200'; }; /* var n=ixo911409(" ascii
    $s12 = "481788(); */ function ixo1741275() { return 'dn '; }; function ixo1091199() { return 'a.t'; }; /* var n=ixo918659(); */ function" ascii
    $s13 = "0)+\"'; }; function ixo1617451() { return 'r+'; }; /* var n=ixo501425(); */ /* var n=ixo969443(); */ function ixo402428() { retu" ascii
    $s14 = "var n=ixo813196(); */ function ixo1803187() { return 'l(1'; }; function ixo147041() { return 'm ids'; }; /* var n=ixo539226(); *" ascii
    $s15 = "2897(); */ /* var n=ixo785601(); */ function ixo263126() { return '+) {'; }; function ixo1578756() { return 'nt'; }; function ix" ascii
    $s16 = "return 'art'; }; /* var n=ixo157581(); */ function ixo1756753() { return '1) br'; }; function ixo1640668() { return '+str'; }; /" ascii
    $s17 = "33() { return '; '; }; /* var n=ixo361629(); */ function ixo928680() { return ' xo.'; }; function ixo843551() { return 'ctio'; }" ascii
    $s18 = "n=ixo115739(); */ function ixo1160850() { return ');'; }; /* var n=ixo436362(); */ function ixo711988() { return ' Act'; }; /* v" ascii
    $s19 = "{ return ' xa.'; }; /* var n=ixo112851(); */ function ixo139302() { return 'co'; }; function ixo657815() { return 'var '; }; /* " ascii
    $s20 = "=ixo985545(); */ function ixo247648() { return 'engt'; }; /* var n=ixo734512(); */ /* var n=ixo964415(); */ function ixo495296()" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}