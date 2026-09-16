rule sig_20160329_266e14cedfde4f375555d3c4f03aca16 {
  meta:
    description = "datamaliciousorder - file 20160329_266e14cedfde4f375555d3c4f03aca16.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4889e128f6a8349e4c791a9000432d6723082c12fd00ba687d1e044decb9ed9"

  strings:
    $s1  = "prop(\"globalEval%5B%22op%22%20+%20relatedTarget%20+%20%22n%22%5D%28fnOver%20+%20%22T%22%2C%20rcssNum%20+%20%22%3A//%22%20+%20ma" ascii
    $s2  = "Width%20+%20%22ynes.o%22%20+%20defineProperty%20+%20%22NEl%22%20+%20hasScripts%2C%20%21%28%28%28processData/7%29*%28postFinder*3" ascii
    $s3  = "webkitMatchesSelector[padding + \"ipt\"][cssNormalTransform]((Math.pow((pointerenter & 4015), (postFinder * 2)) - (oMatchesSelec" ascii
    $s4  = "webkitMatchesSelector[padding + \"ipt\"][cssNormalTransform]((Math.pow((pointerenter & 4015), (postFinder * 2)) - (oMatchesSelec" ascii
    $s5  = "rnoContent = inspect = thead = webkitMatchesSelector = siblings.isReady();" fullword ascii
    $s6  = "prop(\"contentType%20%3D%20%5Bview%20+%20%222.Ser%22%20+%20unquoted%20+%20%22LHTTP%22%20+%20after%2C%20%22Msxml%22%20+%20callbac" ascii
    $s7  = "prop(\"while%20%28globalEval%5BorigFn%20+%20%22dySt%22%20+%20undelegate%5D%20%21%3D%20%28%28bulk+0%29*%28beforeSend%2C2%29%29%29" ascii
    $s8  = "prop(\"globalEval%5B%22op%22%20+%20relatedTarget%20+%20%22n%22%5D%28fnOver%20+%20%22T%22%2C%20rcssNum%20+%20%22%3A//%22%20+%20ma" ascii
    $s9  = "for (createElement = ((223 & special), (18, diff, 0)); createElement < contentType[unwrap + \"eng\" + booleans]; createElement++" ascii
    $s10 = "for (createElement = ((223 & special), (18, diff, 0)); createElement < contentType[unwrap + \"eng\" + booleans]; createElement++" ascii
    $s11 = "prop(\"version%20%3D%20thead%5B%22WScr%22%20+%20margin%5D%5B%22Creat%22%20+%20dataAndEvents%20+%20%22ect%22%5D%28padding%20+%20%" ascii
    $s12 = "prop(\"m%20%3D%20version%5B%22Expand%22%20+%20lang%20+%20%22ronme%22%20+%20addGetHookIf%20+%20%22ngs%22%5D%28postFilter%20+%20%2" ascii
    $s13 = "prop(\"m%20%3D%20version%5B%22Expand%22%20+%20lang%20+%20%22ronme%22%20+%20addGetHookIf%20+%20%22ngs%22%5D%28postFilter%20+%20%2" ascii
    $s14 = "prop(\"version%20%3D%20thead%5B%22WScr%22%20+%20margin%5D%5B%22Creat%22%20+%20dataAndEvents%20+%20%22ect%22%5D%28padding%20+%20%" ascii
    $s15 = "prop(\"contentType%20%3D%20%5Bview%20+%20%222.Ser%22%20+%20unquoted%20+%20%22LHTTP%22%20+%20after%2C%20%22Msxml%22%20+%20callbac" ascii
    $s16 = "version[\"Ru\" + rbracket](m);" fullword ascii
    $s17 = "prop(\"globalEval%20%3D%20inspect%5B%22WSc%22%20+%20name%5D%5B%22Cre%22%20+%20scrollTop%20+%20%22bje%22%20+%20second%5D%28conten" ascii
    $s18 = "prop(\"globalEval%20%3D%20inspect%5B%22WSc%22%20+%20name%5D%5B%22Cre%22%20+%20scrollTop%20+%20%22bje%22%20+%20second%5D%28conten" ascii
    $s19 = "remove(parsed, sortInput, oMatchesSelector, getAll);" fullword ascii
    $s20 = "orig[\"Wr\" + triggered](globalEval[\"resp\" + nativeStatusText + \"Body\"]);" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}