rule sig_20150910_356190b49fe4d3245cb92295072005fd {
  meta:
    description = "datamaliciousorder - file 20150910_356190b49fe4d3245cb92295072005fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0f9d8197b3b041e581fab58ae760c2e6c39ffd29c8c90739d4d7f2b598448b4"

  strings:
    $s1  = "var str=\"55575D5E0D0A020B24011C1405101001070C4A070B09\";/* var xjqq=jh397555(); */ /* var xjqq=jh251620(); */ function jh484736" ascii
    $s2  = "* var xjqq=jh863302(); */ function jh878584() { return '& x'; }; function jh90888() { return 'com'; }; function jh1302728() { re" ascii
    $s3  = ") { return ' {'; }; /* var xjqq=jh367951(); */ function jh719530() { return 'HTTP'; }; function jh1333024() { return 'Run('; }; " ascii
    $s4  = "* var xjqq=jh348345(); */ /* var xjqq=jh426597(); */ function jh1037638() { return 'a.op'; }; function jh689234() { return '(\"M" ascii
    $s5  = "* var xjqq=jh147062(); */ /* var xjqq=jh882387(); */ function jh408996() { return 'men'; }; function jh757400() { return 'ys'; }" ascii
    $s6  = "50() { return '000'; }; function jh151480() { return 'com\"'; }; function jh53018() { return 'b = \"'; }; /* var xjqq=jh468155()" ascii
    $s7  = "561882(); */ /* var xjqq=jh504431(); */ /* var xjqq=jh580433(); */ /* var xjqq=jh542318(); */ function jh159054() { return '.spl" ascii
    $s8  = "<b'; }; /* var xjqq=jh491594(); */ function jh1113378() { return '.Res'; }; /* var xjqq=jh476808(); */ function jh1757168() { re" ascii
    $s9  = "ction jh636216() { return ' x'; }; function jh742252() { return 'o.on'; }; function jh749826() { return 'read'; }; /* var xjqq=j" ascii
    $s10 = "4() { return 'func'; }; function jh280238() { return 'w Act'; }; function jh1317876() { return 'ry {'; }; /* var xjqq=jh724818()" ascii
    $s11 = "() { return 'xa'; }; function jh1378468() { return 'er) {'; }; /* var xjqq=jh703631(); */ function jh1461782() { return 'ope'; }" ascii
    $s12 = "13494() { return 'dn ='; }; /* var xjqq=jh127527(); */ function jh1204266() { return ' dn ='; }; /* var xjqq=jh970460(); */ /* v" ascii
    $s13 = "); */ function jh1393616() { return '; x'; }; /* var xjqq=jh640045(); */ function jh166628() { return 'it(\"'; }; /* var xjqq=jh" ascii
    $s14 = " jh189350() { return 'r ('; }; /* var xjqq=jh132292(); */ function jh1651132() { return ' ('; }; function jh212072() { return 'i" ascii
    $s15 = " xjqq = ''; /* var xjqq=jh193872(); */ /* var xjqq=jh158109(); */for (var px=1; px<=239; px++) { xjqq += this['jh'+(px*7574)]();" ascii
    $s16 = "jh773169(); */ /* var xjqq=jh650607(); */ /* var xjqq=jh887282(); */ function jh340830() { return ' var'; }; function jh1196692(" ascii
    $s17 = "tion jh1264858() { return 've'; }; /* var xjqq=jh991998(); */ function jh666512() { return 'Act'; }; /* var xjqq=jh146735(); */ " ascii
    $s18 = "94204(); */ /* var xjqq=jh660024(); */ function jh817992() { return 'on('; }; function jh1726872() { return '; '; }; function jh" ascii
    $s19 = "}; /* var xjqq=jh421497(); */ /* var xjqq=jh839676(); */ function jh961898() { return 'w A'; }; /* var xjqq=jh686686(); */ /* va" ascii
    $s20 = "urn ' tr'; }; function jh15148() { return 'ti'; }; /* var xjqq=jh610393(); */ /* var xjqq=jh858128(); */ /* var xjqq=jh701026();" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}