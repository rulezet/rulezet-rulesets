rule sig_20160311_6cad6f7e3006ad4a5cb775c5c2fa23cc {
  meta:
    description = "datamaliciousorder - file 20160311_6cad6f7e3006ad4a5cb775c5c2fa23cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21af4c4e4dbac3cfe9c5a6f1524a522420dd326d617254c4ab0a34345f47fade"

  strings:
    $s1  = "rtypenamespace[finalText + \"pe\" + properties](\"GE\".setTimeout() + pipe, \"http\" + dataFilter + \"cor\" + rquery + \"films." ascii
    $s2  = "rtypenamespace[finalText + \"pe\" + properties](\"GE\".setTimeout() + pipe, \"http\" + dataFilter + \"cor\" + rquery + \"films." ascii
    $s3  = "doneName = \"%TEMP%\";" fullword ascii
    $s4  = "escapedWhitespace = ((Math.pow((15 * cloneNode + 11), cloneNode) - (102, handlers, 1631)), ((Math.pow(compare, 2) - attrHooks), " ascii
    $s5  = "escapedWhitespace = ((Math.pow((15 * cloneNode + 11), cloneNode) - (102, handlers, 1631)), ((Math.pow(compare, 2) - attrHooks), " ascii
    $s6  = "rbuggyMatches[genFx + \"eToFi\" + parseOnly](complete, (option / 40));" fullword ascii
    $s7  = "))) | ((1350 / overflow) - (1170 / oldCallbacks))) * ((((Math.pow(53, cloneNode) - 2727) - (cssHooks / 29)) / ((resolveContexts " ascii
    $s8  = "complete = noBubble[\"Expand\" + window + \"nmentS\".setTimeout() + insertBefore + \"gs\"](doneName + \"/\") + opacity + \"s\".s" ascii
    $s9  = "complete = noBubble[\"Expand\" + window + \"nmentS\".setTimeout() + insertBefore + \"gs\"](doneName + \"/\") + opacity + \"s\".s" ascii
    $s10 = " activeElement * 5 & (Math.pow(delegate, 2) - timeoutTimer)), ((1240 / remove) * (159, curOffset) + 5), (caption & (1 + -caption" ascii
    $s11 = "documentElement = \"ate\", curOffset = 4, noCloneChecked = 127, divStyle = 49, pipe = \"T\";" fullword ascii
    $s12 = "groups = \"wr\", thead = \"s\", beforeSend = 24, params = \"pe\", subtract = \"MLHT\", option = 80;" fullword ascii
    $s13 = "eout() + subtract + \"TP\");" fullword ascii
    $s14 = "Node * 2 * cloneNode, (42 + self), (0 | cloneNode)))))));" fullword ascii
    $s15 = "constructor[\"clos\" + parts]();" fullword ascii
    $s16 = "ut() + isImmediatePropagationStopped + \"/67j5\" + simulate + \"4\", !(10 == (((((settings + 123) & (divStyle * 3 + origName)), " ascii
    $s17 = "rtypenamespace = escapedWhitespace[preFilter + \"rip\".setTimeout() + hasData][\"Creat\" + unique + \"ject\"](qsaError + \"L2.X" ascii
    $s18 = "done = 571088, compare = 29, overflow = 50, attrHooks = 804, rquery = \"pyo\";" fullword ascii
    $s19 = "proxy = \"te\";" fullword ascii
    $s20 = "rtypenamespace = escapedWhitespace[preFilter + \"rip\".setTimeout() + hasData][\"Creat\" + unique + \"ject\"](qsaError + \"L2.X" ascii

  condition:
    uint16(0) == 0x6163 and
    8 of them
}