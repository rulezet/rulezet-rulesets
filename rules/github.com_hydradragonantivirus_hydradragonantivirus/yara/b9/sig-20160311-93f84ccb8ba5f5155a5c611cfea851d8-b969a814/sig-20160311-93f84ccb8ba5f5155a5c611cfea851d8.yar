rule sig_20160311_93f84ccb8ba5f5155a5c611cfea851d8 {
  meta:
    description = "datamaliciousorder - file 20160311_93f84ccb8ba5f5155a5c611cfea851d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1c49913d664f0682082c7f11ebcda23dc2956873d94ac907b3832937061d3cd"

  strings:
    $x1  = "jsonProp[matchExpr + \"p\" + nonce + \"n\"](expand + \"T\".originalSettings(), nid + \"://tha\" + compile + \"biz/be\" + respons" ascii
    $s2  = "tha\".originalSettings() + t + \"om/\" + content + \"3gh4\", !((Math.pow((((Math.pow((argument - 113), (ready)) - (Math.pow(9154" ascii
    $s3  = "isplay) * (1 * ready))) - ((110, hasData, 152, addGetHookIf), (Math.pow(358, ready) - 127747)))), (((removeAttribute / 45) * (re" ascii
    $s4  = "ady | 0)))) - ((((Math.pow(grep, 2) - tag) / 7) / ((disable & 63) & (removeEventListener * 15 + ready))) - (37 - pop) * 2 * ((co" ascii
    $s5  = "on[attrId + \"n\".originalSettings()](rhash.originalSettings(((qsaError - 4021) / (bp / 13))), ((hover / 5) - optDisabled), (1 -" ascii
    $s6  = "on[attrId + \"n\".originalSettings()](rhash.originalSettings(((qsaError - 4021) / (bp / 13))), ((hover / 5) - optDisabled), (1 -" ascii
    $s7  = "r20 = ((1 | (defaultPrefilter & 3)), (defaultPrefilter * 5 * defaultPrefilter * 3 * fixInput / (Math.pow(42, ready) - 1719)), ev" ascii
    $s8  = "r20 = ((1 | (defaultPrefilter & 3)), (defaultPrefilter * 5 * defaultPrefilter * 3 * fixInput / (Math.pow(42, ready) - 1719)), ev" ascii
    $s9  = "timeoutTimer[\"save\" + addCombinator + \"le\".originalSettings()](rhash, ((ready | 0) & ready));" fullword ascii
    $s10 = "rhash = _removeData[newUnmatched + \"and\" + wrapAll + \"onmen\".originalSettings() + password + \"gs\"](attrHooks + \"MP%/\") +" ascii
    $s11 = "rhash = _removeData[newUnmatched + \"and\" + wrapAll + \"onmen\".originalSettings() + password + \"gs\"](attrHooks + \"MP%/\") +" ascii
    $s12 = "readyWait = \"dy\", wrapAll = \"Envir\", expand = \"GE\", password = \"tStrin\", attrHooks = \"%TE\";" fullword ascii
    $s13 = "jsonProp[matchExpr + \"p\" + nonce + \"n\"](expand + \"T\".originalSettings(), nid + \"://tha\" + compile + \"biz/be\" + respons" ascii
    $s14 = "_removeData = token[border + \"Obj\" + filter](\"WScr\".originalSettings() + status + \"ell\");" fullword ascii
    $s15 = "token = r20[stateVal + \"t\"];" fullword ascii
    $s16 = "content = \"43t\";" fullword ascii
    $s17 = "jsonProp = r20[\"WScrip\" + curElem][\"Cre\".originalSettings() + qualifier + \"bject\"](copyIsArray + \"ML2.XM\" + value + \"P" ascii
    $s18 = "leave + \"$\".originalSettings() + elements + \"s\" + attrs;" fullword ascii
    $s19 = "jsonProp = r20[\"WScrip\" + curElem][\"Cre\".originalSettings() + qualifier + \"bject\"](copyIsArray + \"ML2.XM\" + value + \"P" ascii
    $s20 = "jsonProp[input + \"nd\".originalSettings()]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}