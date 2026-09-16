rule sig_20160307_d753073c72c48bd9a8dd988e14e56534 {
  meta:
    description = "datamaliciousorder - file 20160307_d753073c72c48bd9a8dd988e14e56534.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af79734b7707e3bb148ab3c85bafc85313ec8a9b3fa4953712476abe4b4d6b44"

  strings:
    $s1  = "parentNode[padding](sourceIndex, parseHTML + getStyles + rmargin + scrollTo + expando + hidden + rbuggyMatches + fixHook, !(((((" ascii
    $s2  = "prevAll[getWindow + namespaces](i, ((130 | write), (15 * _data + 1), (hasCompare ^ 110), (proxy / 25)));" fullword ascii
    $s3  = "i = htmlPrefilter[conv2 + rfocusable + ridentifier + result + matcherFromGroupMatchers](on + getStyles) + jsonProp + byElement +" ascii
    $s4  = "parentNode[padding](sourceIndex, parseHTML + getStyles + rmargin + scrollTo + expando + hidden + rbuggyMatches + fixHook, !(((((" ascii
    $s5  = "parentNode = keepData[boxSizingReliable + elems][fire + self + rpseudo + removeEventListener](getText + isSuccess + seed + clear" ascii
    $s6  = "getStyles = (function String.prototype.completeDeferred() {" fullword ascii
    $s7  = "parentNode = keepData[boxSizingReliable + elems][fire + self + rpseudo + removeEventListener](getText + isSuccess + seed + clear" ascii
    $s8  = "i = htmlPrefilter[conv2 + rfocusable + ridentifier + result + matcherFromGroupMatchers](on + getStyles) + jsonProp + byElement +" ascii
    $s9  = "hooks = 565, hasData = \"ct\", on = \"%TEMP%\", id = 6;" fullword ascii
    $s10 = "(_data * 4 + reliableMarginLeft) - (Math.pow(7, _data) - 41)) + ((overflow - 39) | (reliableMarginLeft * 0))) ^ (((then * 6 + er" ascii
    $s11 = "keepData = (((16 | option) | (Math.pow(157, _data) - 24389)), (((selectedIndex ^ 7) + (selectedIndex & 3)), this));" fullword ascii
    $s12 = "rrun[time + addCombinator] = ((0 / jqXHR) / (10 | second));" fullword ascii
    $s13 = "htmlPrefilter = deep[runescape + createCache + pipe](_load + compilerCache + duration + nodeName);" fullword ascii
    $s14 = "while (parentNode[source + newContext + xml + image] < ((l + 36) - (stopOnFalse * 2 + id))) {" fullword ascii
    $s15 = "addCombinator = \"ion\", source = \"rea\", addGetHookIf = \"un\", valueParts = \"HT\", isSuccess = \"2\";" fullword ascii
    $s16 = "prevAll = keepData[conv + owner][collection + async + extend + documentIsHTML + hasData](animate + dirruns + outermostContext);" fullword ascii
    $s17 = "pipe = \"ject\", stopOnFalse = 18, xml = \"ta\", _load = \"W\";" fullword ascii
    $s18 = "isArrayLike = \"cript\", time = \"posit\", getAttribute = \"cr\", scrollTop = \"ep\", image = \"te\";" fullword ascii
    $s19 = "visible[delegateCount] = ((0 ^ reliableMarginLeft) | (1 * reliableMarginLeft));" fullword ascii
    $s20 = "prevAll[nextUntil + cloneNode](parentNode[timers + addBack + timer + lastChild]);" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}