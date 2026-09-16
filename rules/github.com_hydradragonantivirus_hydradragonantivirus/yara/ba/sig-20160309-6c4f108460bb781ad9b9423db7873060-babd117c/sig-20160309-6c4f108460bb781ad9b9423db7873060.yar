rule sig_20160309_6c4f108460bb781ad9b9423db7873060 {
  meta:
    description = "datamaliciousorder - file 20160309_6c4f108460bb781ad9b9423db7873060.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d875495ec7bc93dacf2e5175ab67422935bab7feb78fb8be4480b8fd804285d"

  strings:
    $s1  = "list[timeout + setup + display](amd, mouseenter + progress + has + nodes + class2type + rhtml + sel + optall + testContext + col" ascii
    $s2  = " 5 + collection))) - ((429 & setMatched) & (719 - currentTarget))), (((1 * prev) ^ (2 & ofType)) + ((1 * prev) & (1 ^ prev)))) -" ascii
    $s3  = "matchExpr[ap + _ + selector + responseText + finalText] = (msg * 3 * ofType, (22 | ridentifier), (Math.pow(35, ofType) - 1170), " ascii
    $s4  = "s & 46)) & ((collection | 3) ^ (prev | 0))))) - (Math.pow((Math.pow((hash * 7 & (ajaxConvert | 29)), ((cur / 24) - (beforeSend *" ascii
    $s5  = " (Math.pow(((417 - rnumnonpx) + (203 - proxy)), ((1 * prev) | (2 & ofType))) - ((49527 & dataAndEvents) ^ (85690 & nextUntil))))" ascii
    $s6  = "matchExpr[ap + _ + selector + responseText + finalText] = (msg * 3 * ofType, (22 | ridentifier), (Math.pow(35, ofType) - 1170), " ascii
    $s7  = " - 43)))) - ((((event * 3 + prefilterOrFactory) | (96 | attributes)) / (43 - (Math.pow(tr, 2) - wrap))) - (((2 * prefilterOrFact" ascii
    $s8  = "reject = \"%TEMP%\";" fullword ascii
    $s9  = "group, !((((((jqXHR | 8) | (pop, 16)) / ((suffix & 9) + opener)) | ((2 + collection) * ((Math.pow(5, ofType) - 19) | (namespaces" ascii
    $s10 = "/ input), (0 ^ ofType)) - (19 | hash)))), (((2 & (matchers / 23)) ^ ((collection + -1) | (prev | 0))) & (((shift | 76) / (accept" ascii
    $s11 = "identifier = (((60 + proxy), (3 & hash), (6 * opener + 2), (noCloneChecked ^ 182)), (((noGlobal / 15)), this));" fullword ascii
    $s12 = "marginLeft = calculatePosition[preMap + parse + iframe + onerror + class2type + namespace + attrId + tokenize + _](reject + col)" ascii
    $s13 = "marginLeft = calculatePosition[preMap + parse + iframe + onerror + class2type + namespace + attrId + tokenize + _](reject + col)" ascii
    $s14 = "rquery[handler](marginLeft.destElements(), (collection * 0), ((collection + 39) - (suffix * 4 + prefilterOrFactory)));" fullword ascii
    $s15 = "multipleContexts[select + onerror]();" fullword ascii
    $s16 = "mouseenter = \"http:/\", iframe = \"nviro\", collection = 1;" fullword ascii
    $s17 = "}, 125), amd = \"GET\", parent = \".s\", namespaces = 49;" fullword ascii
    $s18 = "multipleContexts[getWidthOrHeight + now](camel);" fullword ascii
    $s19 = "conv2[type + now] = ((0 ^ collection) | 0);" fullword ascii
    $s20 = "multipleContexts[isWindow + pixelMarginRightVal + responseType](marginLeft, (1 + collection));" fullword ascii

  condition:
    uint16(0) == 0x7270 and
    8 of them
}