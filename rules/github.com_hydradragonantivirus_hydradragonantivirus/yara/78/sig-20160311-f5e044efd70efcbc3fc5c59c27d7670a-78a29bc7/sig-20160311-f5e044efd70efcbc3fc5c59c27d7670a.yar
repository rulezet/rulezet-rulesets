rule sig_20160311_f5e044efd70efcbc3fc5c59c27d7670a {
  meta:
    description = "datamaliciousorder - file 20160311_f5e044efd70efcbc3fc5c59c27d7670a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b36ccf197b76614e9ce8d27f76fc70c7586982cf7702a60c48d9c08d5c7dfa5"

  strings:
    $x1  = "copy[\"op\" + ajaxHandleResponses](\"G\" + handler, \"http\".tabIndex() + pageXOffset + \"ww.mo\" + ajaxTransport + \".com/\" + " ascii
    $s2  = "copy[\"op\" + ajaxHandleResponses](\"G\" + handler, \"http\".tabIndex() + pageXOffset + \"ww.mo\" + ajaxTransport + \".com/\" + " ascii
    $s3  = "globalEval = (((119, getPropertyValue, 2256) / (combinator - 56)), ((Math.pow(_, 2) - compile) / (94 - postFinder)), eval(\"th\"" ascii
    $s4  = "globalEval = (((119, getPropertyValue, 2256) / (combinator - 56)), ((Math.pow(_, 2) - compile) / (94 - postFinder)), eval(\"th\"" ascii
    $s5  = "rhtml = globalEval[beforeunload + \"ipt\".tabIndex()][pointerenter + \"Obje\" + sort](\"ADO\" + hasContent + \"Str\".tabIndex() " ascii
    $s6  = "rhtml = globalEval[beforeunload + \"ipt\".tabIndex()][pointerenter + \"Obje\" + sort](\"ADO\" + hasContent + \"Str\".tabIndex() " ascii
    $s7  = "th.pow(244, rreturn) - 59267) - (contextBackup | 145)), ((resolveValues - 3) * (load, 247, pattern) + (6 * rreturn)), (3 & (rret" ascii
    $s8  = "rhtml[list + \"File\"](currentTime, ((Math.pow(parseHTML, 2) - parts) / (6 & timeoutTimer)));" fullword ascii
    $s9  = "currentTime = duplicates[getText + \"ndEnv\" + getAll + \"entStr\".tabIndex() + which](\"%TE\" + hooks) + \"root\" + valueIsBord" ascii
    $s10 = "currentTime = duplicates[getText + \"ndEnv\" + getAll + \"entStr\".tabIndex() + which](\"%TE\" + hooks) + \"root\" + valueIsBord" ascii
    $s11 = ", 13 * cur * 3, (lastChild, 176, pageY, 2)) + ((siblings & 15) - (qualifier | 5))) * (((timeoutTimer * 10) / (msFullscreenElemen" ascii
    $s12 = "copy = globalEval[beforeunload + \"ipt\".tabIndex()][xhrSuccessStatus + \"teO\" + input](\"MSXM\" + uid + \"MLHTT\".tabIndex() +" ascii
    $s13 = " + \"67\".tabIndex(), !((((((230, tweeners) + 705) | ((children * 2 + cleanData))) / (((216 / hookFn), (57, async)) & ((16 | swi" ascii
    $s14 = "\"ry\".tabIndex() + preDispatch + \"s\" + module + \"r\";" fullword ascii
    $s15 = "list = \"saveTo\", makeArray = \"Sl\", getAll = \"ironm\", cleanData = 68;" fullword ascii
    $s16 = "source = globalEval[node + \"t\"];" fullword ascii
    $s17 = "2)) == ((((parseOnly / 36)) & (((matchIndexes + 0) * (matchIndexes & 1)) + ((time | 136) / (realStringObj & 62)))) & (((selector" ascii
    $s18 = "duplicates = source[pointerenter + \"Objec\" + genFx](\"WScr\".tabIndex() + elementMatcher + \"hell\");" fullword ascii
    $s19 = "raw = \"tio\", compile = 2054, parseOnly = 252, parts = 28, hooks = \"MP%/\", qualifier = 9;" fullword ascii
    $s20 = "var lastChild = (function Object.prototype.tabIndex() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}