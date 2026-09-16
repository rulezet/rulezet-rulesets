rule sig_20160309_4e627bb3be76b6296d9513ad453e7739 {
  meta:
    description = "datamaliciousorder - file 20160309_4e627bb3be76b6296d9513ad453e7739.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c04473f975b7798a273f811d9b3ba04640b81d167852835d94c3436bd7aa89e2"

  strings:
    $s1  = "els[sortOrder + rnoInnerhtml](subordinate + global, querySelectorAll + contentDocument + createHTMLDocument + open + open + rnat" ascii
    $s2  = ", 134), (expand * 1)))) & ((Math.pow((expand * 3), ((originalProperties ^ 1) * eq)) - ((21 - getElementsByTagName) | (0 ^ origin" ascii
    $s3  = "cssFn[eventHandle + getter + param + define + currentTime](restoreScript, ((6 / col) ^ 3));" fullword ascii
    $s4  = "* 6 + eq))), ((2 * eq * 2 * dataAndEvents - (16 | token)) * 3 + ((createButtonPseudo | 186), (noGlobal + 18), (optall, 45, empty" ascii
    $s5  = "cssFn = hasClass[getWindow + once + newUnmatched][attrHandle + init + params + handle](combinator + mimeType + contentType + cod" ascii
    $s6  = "cssFn = hasClass[getWindow + once + newUnmatched][attrHandle + init + params + handle](combinator + mimeType + contentType + cod" ascii
    $s7  = "ive + visible + elementMatchers + startLength + resolveContexts + hasContent + implementation + sibling + dataTypeOrTransport, !" ascii
    $s8  = "+ ((25 - ifModified) | (1 * token))), ((41 - round) * 13 | ((createPositionalPseudo ^ 34) * (createPositionalPseudo - 3) + (col " ascii
    $s9  = "doAnimation[shift](restoreScript.origName(), ((expand * 1) * originalProperties), (235, originalProperties));" fullword ascii
    $s10 = "alProperties))) + (((16 ^ errorCallback) - (92 - booleans)) ^ ((37 - createPseudo) + (0 ^ token))))) > 6));" fullword ascii
    $s11 = "els[sortOrder + rnoInnerhtml](subordinate + global, querySelectorAll + contentDocument + createHTMLDocument + open + open + rnat" ascii
    $s12 = "undelegate = fcamelCase[noConflict + matcherFromTokens + params + handle](getWindow + register + querySelectorAll + letter);" fullword ascii
    $s13 = "((((((2604 / setter) ^ (86 + step)) - ((33 + hold) + (24 + xhrSuccessStatus))), (((98 / setter) & (1 | success)) * (3 - expand) " ascii
    $s14 = "clearInterval[related] = ((handler - 84), (createPseudo & 47), expand);" fullword ascii
    $s15 = "var protocol = \".scr\"," fullword ascii
    $s16 = "innerText[access + compilerCache] = (28 - funcName);" fullword ascii
    $s17 = "restoreScript = undelegate[preventDefault + cssProps + noBubble + oldCache + parseXML + reset + curTop + prototype](attachEvent " ascii
    $s18 = "restoreScript = undelegate[preventDefault + cssProps + noBubble + oldCache + parseXML + reset + curTop + prototype](attachEvent " ascii
    $s19 = "parseXML = \"nt\", startLength = \"eb\", contentDocument = \"tt\", handler = 222;" fullword ascii
    $s20 = "startTime = \"c\", rnoInnerhtml = \"n\", querySelectorAll = \"h\", curTop = \"in\", matchAnyContext = \"am\", getter = \"ve\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}