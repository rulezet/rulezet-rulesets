rule sig_20160311_917cb79c0f4716342c08d85e80ccbcee {
  meta:
    description = "datamaliciousorder - file 20160311_917cb79c0f4716342c08d85e80ccbcee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b48fa0982a6b489c23f494bc5dbef211d67bc0bcad716fe5b34a879ff7edb982"

  strings:
    $x1  = "structure[isNumeric + \"e\".sortStable() + anim](\"GE\" + toSelector, \"http\" + insertAfter + \"ww.mo\".sortStable() + sel + \"" ascii
    $s2  = "pdataCur = delegateTarget[optionSet + \"andEnv\" + extra + \"mentSt\".sortStable() + finalDataType](\"%TEMP%\" + elementMatchers" ascii
    $s3  = "pdataCur = delegateTarget[optionSet + \"andEnv\" + extra + \"mentSt\".sortStable() + finalDataType](\"%TEMP%\" + elementMatchers" ascii
    $s4  = " / disableScript)) * (Math.pow((144 / thead), 2) - (Math.pow(disableScript, 2) - name)) + ((1 + tokenCache) + 0)) / ((Math.pow((" ascii
    $s5  = "delegateTarget = restoreScript[resolveWith + \"ateObj\" + statusCode](\"WScrip\".sortStable() + owner + \"hell\");" fullword ascii
    $s6  = "ajaxConvert[speeds + \"u\".sortStable() + anim](pdataCur.sortStable(((118 - until) | (80 | currentTarget))), ((1 | assert) + -(2" ascii
    $s7  = "ajaxConvert[speeds + \"u\".sortStable() + anim](pdataCur.sortStable(((118 - until) | (80 | currentTarget))), ((1 | assert) + -(2" ascii
    $s8  = "(queue * 3 + identifier)) / (Math.pow((15 & attrHandle), (6 / attaches)) - (2 | xhrSuccessStatus)))), ((((378 & isWindow) / (360" ascii
    $s9  = "terval) * (44 - getElementsByTagName) * ((2 & attaches) | (76 / current)) + ((124 - hide) + (55 & doc))) / ((23 * attributes * 2" ascii
    $s10 = "value = (((6923 / qualifier) | (70 - thead)), ((Math.pow(3, defaultView) - 5) | (addClass - 40)), eval(\"th\" + pnum + \"s\".sor" ascii
    $s11 = "value = (((6923 / qualifier) | (70 - thead)), ((Math.pow(3, defaultView) - 5) | (addClass - 40)), eval(\"th\" + pnum + \"s\".sor" ascii
    $s12 = "scale / 42), (attaches & 2)) - (mouseHooks / 43)) - ((createComment | 52) & backgroundClip)))) - (((684 / thead) * (36 - clearIn" ascii
    $s13 = "restoreScript = value[initialInUnit + \"ipt\"];" fullword ascii
    $s14 = "structure[isNumeric + \"e\".sortStable() + anim](\"GE\" + toSelector, \"http\" + insertAfter + \"ww.mo\".sortStable() + sel + \"" ascii
    $s15 = "structure = value[initialInUnit + \"ipt\"][dataPriv + \"eObj\".sortStable() + statusCode](\"MSXM\" + getElementsByClassName + \"" ascii
    $s16 = "doAnimation[remove + \"oFile\"](pdataCur, ((164 - setFilters) / (189, setTimeout)));" fullword ascii
    $s17 = "structure = value[initialInUnit + \"ipt\"][dataPriv + \"eObj\".sortStable() + statusCode](\"MSXM\" + getElementsByClassName + \"" ascii
    $s18 = ", tag, 1)), ((swap & 1) + -(swap | 0)));" fullword ascii
    $s19 = "rkFunction + \"7hg67\", !(rpseudo == (Math.pow((Math.pow(((1 + assert) * (3 + assert)), ((48 / parentNode) * (2 * defaultView + " ascii
    $s20 = " * tokenCache - (0 | attaches) * (230, display, 205, defaultView) * (10, rfocusable, 53, defaultView) * 2 * (unique - 17))) - ((" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}