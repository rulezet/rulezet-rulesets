rule sig_19360611_23f5eaf84cedb0998e31b34a5f81e4ef {
  meta:
    description = "datamaliciousorder - file 19360611_23f5eaf84cedb0998e31b34a5f81e4ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57fc50d296ebc143c6e4ae4233b7b1d05144456c93c7c8b8aacea4b9c4921018"

  strings:
    $s1 = "obj_more=null;obj_considered=null;obj_packages8=null;obj_better=null;obj_Accuracy=null;obj_alike1=null;obj_large=null;obj_runnin" ascii
    $s2 = "obj_time[{ea1:'\\u0073'}.ea1+{apa0:'\\u0065'}.apa0+{l0:'\\u0074'}.l0+{rea3:'\\u004f'}.rea3+{ven3:'\\u0070'}.ven3+{nf3:'\\u0074'}" ascii
    $s3 = "  \\u0066\\u0069\\u006c\\u0065\\u0074\\u0073[{ata3:'\\u0043'}.ata3+{og3:'\\u006c'}.og3+{o1:'\\u006f'}.o1+{eld0:'\\u0073'}.eld0+{" ascii
    $s4 = "f'}.oo1+{ata2:'\\u006f'}.ata2+{h0:'\\u0072'}.h0]((Math[{ara3:'\\u0072'}.ara3+{ith2:'\\u0061'}.ith2+{ign3:'\\u006e'}.ign3+{at2:'" ascii
    $s5 = "e=\\u0074\\u0065\\u006d\\u0070\\u0031\\u0032+{orr1:'\\u005c'}.orr1+{r2:'\\u005c'}.r2+Math.floor((Math[{ara3:'\\u0072'}.ara3+{ith" ascii
    $s6 = "'}.at2+{xt3:'\\u006f'}.xt3+{ar3:'\\u006d'}.ar3]() * (200)) + 1), false);    obj_time[{l1:'\\u0073'}.l1+{ccu1:'\\u0065'}.ccu1+{a0" ascii

  condition:
    uint16(0) == 0x626f and
    all of them
}