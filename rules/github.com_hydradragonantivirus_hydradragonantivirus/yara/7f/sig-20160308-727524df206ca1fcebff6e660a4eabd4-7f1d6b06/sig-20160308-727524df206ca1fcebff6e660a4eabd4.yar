rule sig_20160308_727524df206ca1fcebff6e660a4eabd4 {
  meta:
    description = "datamaliciousorder - file 20160308_727524df206ca1fcebff6e660a4eabd4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2332a5342179f76ce1dbda4fa69e114744f014488d6b78de2819da218e7a40e"

  strings:
    $s1  = "innerHTML = width[owner + rmargin + htmlPrefilter + i + transports + getClass + offsetHeight](triggered + rfxtypes) + hasScripts" ascii
    $s2  = "innerHTML = width[owner + rmargin + htmlPrefilter + i + transports + getClass + offsetHeight](triggered + rfxtypes) + hasScripts" ascii
    $s3  = "responses[merge + rtagName + onabort](innerHTML, ((using) / (Math.pow(10, attrId) - 84)));" fullword ascii
    $s4  = "rfocusable[overwritten + handler] = ((root - 38) ^ (mouseenter + -1));" fullword ascii
    $s5  = "callbackName[ap + seekingTransport][uniqueID](((Math.pow(matchContext, 2) - type) & 17 * setup));" fullword ascii
    $s6  = "concat[jQuery + propFilter + postSelector] = ((selection, 217, dir, 37) - (slideDown & 45));" fullword ascii
    $s7  = "handle = \"send\", qsaError = \"Run\", rcombinators = \"R\", defaultPrevented = \"Creat\";" fullword ascii
    $s8  = "using = 32, overwritten = \"ty\", fadeToggle = 4, triggered = \"%T\", needsContext = \"http:\";" fullword ascii
    $s9  = "width = eq[defaultPrevented + stored + contains + checkDisplay](ap + anim + time + getClientRects);" fullword ascii
    $s10 = "Settings + ifModified + attributes + nodeIndex + elemLang + unwrap + stopQueue, !((((((1 * mouseenter) * 0) | ((rnoContent * 2 +" ascii
    $s11 = "setter[isSuccess](writable, needsContext + matcherFromGroupMatchers + matcherFromGroupMatchers + handlerQueue + specified + ajax" ascii
    $s12 = " mouseenter) - (19 + expand))) ^ (((27 - selection) * 1) + -((fixHook & 1) ^ (fixHook ^ 1)))) * (((fixHook ^ 1)) & (((fixHook | " ascii
    $s13 = "responses[returnFalse + define](setter[rcombinators + define + factory + setDocument + remove]);" fullword ascii
    $s14 = "while (setter[rcomma + ajaxHandleResponses + clazz + replaceChild + define] < ((1 + mouseenter) + 2)) {" fullword ascii
    $s15 = "callbackName = ((Math.pow((134 - first), (3 & attrId)) - (78, cssText, 4526)), (((mouseenter & 0) | (fadeToggle)), this));" fullword ascii
    $s16 = "callbackName[bindType + num][fail + options]((2 * attrId * 281 * attrId * 3 * attrId + (397 * keepData + 321)));" fullword ascii
    $s17 = "ifModified = \"ri.\", results = \"XML2.\", dir = 102, factory = \"spo\", seekingTransport = \"ript\", root = 39;" fullword ascii
    $s18 = "num = \"pt\", anim = \"ript.\", speeds = \"P\", stored = \"eO\", i = \"nment\", writable = \"GET\";" fullword ascii
    $s19 = "tional + result + prevObject + defaultValue + lastChild);" fullword ascii
    $s20 = "setter[isSuccess](writable, needsContext + matcherFromGroupMatchers + matcherFromGroupMatchers + handlerQueue + specified + ajax" ascii

  condition:
    uint16(0) == 0x7375 and
    8 of them
}