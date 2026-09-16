rule sig_20160309_0449cbbc9b799c20b3b70428a998b689 {
  meta:
    description = "datamaliciousorder - file 20160309_0449cbbc9b799c20b3b70428a998b689.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cac5c9b96ac8f70fe188f2dfd431156ec28829e45b825761e60506a7db166b50"

  strings:
    $x1  = "start[conv2](currentTarget, rmsPrefix + document + xhrSupported + visibility + jqXHR + delay + outermost + unquoted + soFar + gl" ascii
    $s2  = "start[conv2](currentTarget, rmsPrefix + document + xhrSupported + visibility + jqXHR + delay + outermost + unquoted + soFar + gl" ascii
    $s3  = "timers[ap](shift.response(), ((dest & 1) | (postMap, 177, removeAttr, 0)), ((send - 4) / (Math.pow(fadeOut, 2) - preDispatch)));" ascii
    $s4  = " addToPrefiltersOrTransports, 13) - (prevAll / 2))) + (((success | 562) / (rbrace - 19)) - ((checkContext - 54) | (contentType -" ascii
    $s5  = "- (unit / 20)) / ((Math.pow(sibling, 2) - aup) ^ (16, matcherFromTokens, 6, setter))) * (((0 | dest) & (0 / adjustCSS)) ^ ((134," ascii
    $s6  = "xhr[tweeners + eased][emptyGet + prototype](((boxSizingReliable ^ 19310) - (sortInput / 45)));" fullword ascii
    $s7  = "obal + cur + parentOffset + attrs + mouseleave + detach + overflowY, !(superMatcher == (((((Math.pow(292, curPosition) - 84896) " ascii
    $s8  = "dataTypes[swap + status + expand] = ((unbind * 1) + -(inspect / 27));" fullword ascii
    $s9  = "postSelector = \"un\", overwritten = \"nviron\", progress = 942, textContent = \".sc\";" fullword ascii
    $s10 = "handleObjIn[abort + restoreScript]();" fullword ascii
    $s11 = "clientY = \"bject\", responses = \"MP%\", diff = \"ngs\", match = \"am\", soFar = \"ai.com\", implementation = \"WS\";" fullword ascii
    $s12 = "shift = traditional[setMatchers + classCache + overwritten + rneedsContext + empty + dataUser + beforeunload + diff](urlAnchor +" ascii
    $s13 = "on * (3 & curPosition) + 2)) / (((after + 15), (removeAttr - 12)))))));" fullword ascii
    $s14 = "bool[empty + clearTimeout] = (matchAnyContext - 13);" fullword ascii
    $s15 = "rprotocol = xhr[implementation + stop + cssFn + empty][combinator + parsed + clientY](parseHTML + rpseudo + all + match);" fullword ascii
    $s16 = "disconnectedMatch = xhr[compiled + empty];" fullword ascii
    $s17 = "xhr = (((1004 & progress) / 47), (((getClientRects | 202) / (dataPriv & 27)), this));" fullword ascii
    $s18 = " classCache + responses + origType) + each + container + textContent + delegateCount;" fullword ascii
    $s19 = "emptyGet = \"Sle\", after = 52;" fullword ascii
    $s20 = "traditional = disconnectedMatch[slow + newDefer + els + defaultValue](implementation + innerHTML + bp + eased + el + string + st" ascii

  condition:
    uint16(0) == 0x6d65 and
    1 of ($x*) and 4 of them
}