rule sig_20160311_4f57f141f5c298a3c35e1fd1d013f58c {
  meta:
    description = "datamaliciousorder - file 20160311_4f57f141f5c298a3c35e1fd1d013f58c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a21ef8e418930daa6e9db8366ec96634cf5e9274efcd16a948200a6991a878b2"

  strings:
    $s1  = "curPosition[parseFromString + \"pe\" + computeStyleTests](\"GE\" + addCombinator, \"http\".parents() + swing + \"rfumy\" + Sizzl" ascii
    $s2  = "(1 * defer) + (5 & createPseudo)) - ((116 / rkeyEvent) * (39 - win) + 2)))) - (Math.pow(((createPseudo * 2 / (maxWidth + 6)) + (" ascii
    $s3  = "allTypes[\"R\" + i](innerText.parents(((Math.pow(marginLeft, 2) - async), (Math.pow(197, defer) - 38557), (mozMatchesSelector | " ascii
    $s4  = "allTypes[\"R\" + i](innerText.parents(((Math.pow(marginLeft, 2) - async), (Math.pow(197, defer) - 38557), (mozMatchesSelector | " ascii
    $s5  = "preDispatch = (((171 - Deferred) + 223), ((Math.pow(funescape, 2) - keyHooks) * 3 + (maxWidth + 0)), eval(\"t\" + returnTrue + " ascii
    $s6  = "curPosition[parseFromString + \"pe\" + computeStyleTests](\"GE\" + addCombinator, \"http\".parents() + swing + \"rfumy\" + Sizzl" ascii
    $s7  = "matcherFromTokens = transports[\"Create\" + cssShow + \"ect\".parents()](merge + \"ipt.\" + filters + \"ll\");" fullword ascii
    $s8  = "preDispatch = (((171 - Deferred) + 223), ((Math.pow(funescape, 2) - keyHooks) * 3 + (maxWidth + 0)), eval(\"t\" + returnTrue + " ascii
    $s9  = "(preventDefault | 1) * (preventDefault | 4))), (((defer | 3) + (defer + 1)) / (gotoEnd & 3))) - (((fadeOut + 12), (clone | 84), " ascii
    $s10 = "curPosition = preDispatch[merge + \"ipt\".parents()][tmp + \"teObj\" + isFunction](\"MSXML\" + cssText + \"TTP\".parents());" fullword ascii
    $s11 = " funescape), 43, (onreadystatechange / 15))) + (((hover, 29) - (rwhitespace + 16)) * ((top - 53), defer * 3 * Callbacks * 2, def" ascii
    $s12 = "transports = preDispatch[\"WScri\" + cloneNode];" fullword ascii
    $s13 = "unbind[\"clos\" + name]();" fullword ascii
    $s14 = "rep\" + subtract + \"ka.pl\".parents() + _queueHooks + \"67g5\", !((Math.pow(((((maxWidth + 3) * (maxWidth + 1)) - ((Callbacks *" ascii
    $s15 = "appendChild = preDispatch[\"WScri\".parents() + cloneNode][\"Create\" + cssShow + \"ect\"](to + \"Strea\".parents() + state);" fullword ascii
    $s16 = "arents()) + traditional + \".\" + fns + \"r\";" fullword ascii
    $s17 = "appendChild[preexisting + \"ToFil\".parents() + name](innerText, ((defer & 3) & (gotoEnd & 3)));" fullword ascii
    $s18 = "innerText = matcherFromTokens[calculatePosition + \"ndE\".parents() + handleObj + \"mentSt\" + buildFragment + \"s\"](expand + " ascii
    $s19 = "unbind = appendChild;" fullword ascii
    $s20 = "innerText = matcherFromTokens[calculatePosition + \"ndE\".parents() + handleObj + \"mentSt\" + buildFragment + \"s\"](expand + " ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}