rule sig_20160309_1471ce6678d69fb0f829ffc7f099607f {
  meta:
    description = "datamaliciousorder - file 20160309_1471ce6678d69fb0f829ffc7f099607f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c69c5682b03a08d9aa16d172a3c97512fe7ce96295ec96dc21e646213de867ca"

  strings:
    $s1  = "defer[bindType](_removeData, jsonpCallback + funcName + contexts + dest + anim + outermost + cssShow + dir + requestHeadersNames" ascii
    $s2  = "optall[check + currentTarget]();" fullword ascii
    $s3  = "height = defer[binary + rheader + submit + tfoot];" fullword ascii
    $s4  = "optall[hasContent + closest + whitespace + andSelf + then](createElement, (box / 17));" fullword ascii
    $s5  = "optall = jQuery[match + context][fragment + whitespace + maxIterations + find](responseFields + deepDataAndEvents + fontWeight +" ascii
    $s6  = "one[unshift] = ((contains - 51) | (code & 1));" fullword ascii
    $s7  = "defer[bindType](_removeData, jsonpCallback + funcName + contexts + dest + anim + outermost + cssShow + dir + requestHeadersNames" ascii
    $s8  = " + tfoot + opacity, !((((((stored & 3766) / (stopQueue - 51)), ((rneedsContext - 3123) / (value)), ((220 - isNumeric), (24 | spe" ascii
    $s9  = "es + div) + beforeunload + modified + fadeIn + obj + argument + combinator + qualifier;" fullword ascii
    $s10 = "defer = jQuery[r20 + root][doneName + view + unquoted + prependTo](curPosition + rbuggyQSA + curValue + cos + prototype);" fullword ascii
    $s11 = "pointerenter = jQuery[setAttribute + combinator + set];" fullword ascii
    $s12 = "- byElement) | (34 / box)) * ((1 + tokenize) * (1 * preDispatch))) * ((21 / clearTimeout) * (21 / clearTimeout) * (351 / originA" ascii
    $s13 = "root = \"Script\", curValue = \"M\";" fullword ascii
    $s14 = "outermost = \"system\", combinator = \"c\", stopQueue = 101, contexts = \"/\";" fullword ascii
    $s15 = "defer[protocol + isLocal + rcombinators]();" fullword ascii
    $s16 = "hasContent = \"sa\", check = \"o\";" fullword ascii
    $s17 = "disabled = \"Shell\";" fullword ascii
    $s18 = "preDispatch = 2, obj = \"nt\", diff = \"tion\", requestHeadersNames = \"h\";" fullword ascii
    $s19 = "reset[response + diff] = ((code + 0) + -(useCache - 41));" fullword ascii
    $s20 = "htmlPrefilter[cache](createElement.udataCur(), ((14 * nid + 2) - (oldCache | 44)), ((clearInterval, 187, code) + -(1 * code)));" fullword ascii

  condition:
    uint16(0) == 0x6f70 and
    8 of them
}