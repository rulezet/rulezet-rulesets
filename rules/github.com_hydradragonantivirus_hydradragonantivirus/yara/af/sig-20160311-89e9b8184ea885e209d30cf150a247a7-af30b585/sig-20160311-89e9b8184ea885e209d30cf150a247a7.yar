rule sig_20160311_89e9b8184ea885e209d30cf150a247a7 {
  meta:
    description = "datamaliciousorder - file 20160311_89e9b8184ea885e209d30cf150a247a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "583adacd143ea6fb87ef0187dada0b8334e3b3c5a96db4d5a17311031ee3283c"

  strings:
    $x1  = "always[setFilters + \"p\" + globalEval](\"GE\" + fadeTo, \"http:\".parent() + thead + \"gov.\" + fireWith + \"r35y44\" + v, !(ge" ascii
    $s2  = "ew - 128), (timer + 0)) - (Math.pow(m, 2) - onreadystatechange)) & (Math.pow((152 & stored), 2) - (cors, 193, fadeToggle)))) / (" ascii
    $s3  = "always[setFilters + \"p\" + globalEval](\"GE\" + fadeTo, \"http:\".parent() + thead + \"gov.\" + fireWith + \"r35y44\" + v, !(ge" ascii
    $s4  = "((((Math.pow((96 / xml), (22 / button)) - (Math.pow(104, timer) - 10688)) | (timer * (1 + andSelf) + 1)) + ((Math.pow((defaultVi" ascii
    $s5  = "& transport) * ((1 + xml) + (45 - children))))));" fullword ascii
    $s6  = "((Math.pow((Math.pow(313, timer) - 97458), timer) - (466047 - pageY)) - ((114 - status) + (131, marginLeft, 254, button))) / (3 " ascii
    $s7  = "visibility = rcleanScript[\"Crea\" + elem + \"ect\".parent()](wait + \"pt.Sh\" + removeData);" fullword ascii
    $s8  = "rcleanScript = refElements[teardown + \"rip\" + rinputs];" fullword ascii
    $s9  = "always = refElements[\"WScrip\" + rinputs][\"Creat\".parent() + rheader + \"ject\"](sortStable + \"L2.X\" + cur + \"TTP\".parent" ascii
    $s10 = "}, 35), button = 11, onreadystatechange = 235604217, rinputs = \"t\", thead = \"//nro.\";" fullword ascii
    $s11 = "props[htmlPrefilter + \"u\" + before](b.parent(((load + 73) | (origName + 12))), ((booleans - 25)), ((children - 42) * (crossDom" ascii
    $s12 = "props[htmlPrefilter + \"u\" + before](b.parent(((load + 73) | (origName + 12))), ((booleans - 25)), ((children - 42) * (crossDom" ascii
    $s13 = "refElements = ((Math.pow((89, empty, 121, setMatched), 2) - (win + 13082)), ((callbackName - 42) & (div & 15)), eval(\"th\" + se" ascii
    $s14 = "b = visibility[\"Expand\" + boolHook + \"onm\".parent() + acceptData + \"String\" + currentTime](\"%TE\" + view) + \"am\".parent" ascii
    $s15 = "refElements = ((Math.pow((89, empty, 121, setMatched), 2) - (win + 13082)), ((callbackName - 42) & (div & 15)), eval(\"th\" + se" ascii
    $s16 = "emptyGet = \"nse\", before = \"n\", rbracket = \"sav\", overflow = 330280;" fullword ascii
    $s17 = "b = visibility[\"Expand\" + boolHook + \"onm\".parent() + acceptData + \"String\" + currentTime](\"%TE\" + view) + \"am\".parent" ascii
    $s18 = "pointerleave[rbracket + \"eToFil\" + guaranteedUnique](b, (timer | 0));" fullword ascii
    $s19 = "pointerleave[\"o\".parent() + state + \"n\"]();" fullword ascii
    $s20 = "after[\"clo\".parent() + currentTime + \"e\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}