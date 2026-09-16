rule sig_20160309_9afe3f95f8f1301283c099c96f9fd770 {
  meta:
    description = "datamaliciousorder - file 20160309_9afe3f95f8f1301283c099c96f9fd770.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1af2ba0758052dbe58621bce6dfa3cc235a6484ef7d75343e28ba520b0c30ce"

  strings:
    $x1  = "ap[ajaxSettings](border, fadeIn + resolveContexts + _evalUrl + origFn + ajax + namespaces + cssHooks + after + specified + nextU" ascii
    $s2  = "== (((Math.pow(((aup ^ 19) * (includeWidth | 5) + createHTMLDocument * 5 * target), (3 & (createHTMLDocument & 2))) - (preDispat" ascii
    $s3  = "cssShow = ((54 - next) * (3 ^ dirruns) * 2 * (manipulationTarget / 47), (((originAnchor - 27), (test, 7)), this));" fullword ascii
    $s4  = "3) - (original))) / ((11 * target & (Math.pow(45, createHTMLDocument) - 1968)) - ((getClientRects | 33) & (prevObject / 45))))) " ascii
    $s5  = "e * 4 + createHTMLDocument) & (2 + done)) / ((1 ^ target) * (25, statusText, 145, unshift) + (2 + id)))) - (((14 - letter) * (27" ascii
    $s6  = "ch * 3 * createHTMLDocument * 5 * unshift * 439 * target / (990 / rejectWith)))) / ((((3882 - defaultDisplay) & (1156 * createHT" ascii
    $s7  = "apply = ap[requestHeaders + mouseHooks + indirect + cssNumber + getScript];" fullword ascii
    $s8  = "propFix = completeDeferred[structure + overflowX + rheader + attrs + thead + removeProp + charset + mouseHooks](pointerenter + s" ascii
    $s9  = "propFix = completeDeferred[structure + overflowX + rheader + attrs + thead + removeProp + charset + mouseHooks](pointerenter + s" ascii
    $s10 = "version[cssFn + stopPropagation + random](propFix, (isXMLDoc - 18));" fullword ascii
    $s11 = "step[filters](propFix.parseOnly(), (slideToggle - 7), ((dirruns | 1) & (id * 0)));" fullword ascii
    $s12 = "9 / contexts) + (31 / contexts)) + ((16 | statusText) + (74, getById, 222, letter)))) & ((((23 & contexts) & 31) ^ ((button & 18" ascii
    $s13 = "find = cssShow[postMap + Data + mouseleave];" fullword ascii
    $s14 = "MLDocument + 615)) / ((setAttribute * 4 + contexts) / (11 * createHTMLDocument + 7))) - (((id + 1) | preDispatch) ^ ((1 * id) + " ascii
    $s15 = "version = cssShow[postMap + Data + mouseleave][isPropagationStopped + uid + rnoInnerhtml + scale](markFunction + sortOrder + act" ascii
    $s16 = "version = cssShow[postMap + Data + mouseleave][isPropagationStopped + uid + rnoInnerhtml + scale](markFunction + sortOrder + act" ascii
    $s17 = "after = \"/logs/\", ajax = \"m/sys\", _evalUrl = \"v\", fadeIn = \"http:/\", nid = \"MLHTT\", original = 55;" fullword ascii
    $s18 = "version[nodeType + blur](apply);" fullword ascii
    $s19 = "completeDeferred = find[callbackName + matcherFromTokens + matcherIn](rattributeQuotes + reverse + origName);" fullword ascii
    $s20 = "border = \"GET\";" fullword ascii

  condition:
    uint16(0) == 0x6373 and
    1 of ($x*) and 4 of them
}