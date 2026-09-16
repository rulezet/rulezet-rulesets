rule sig_20160308_531514491ff4c65e3a06f02d6c034a35 {
  meta:
    description = "datamaliciousorder - file 20160308_531514491ff4c65e3a06f02d6c034a35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44ddc0277d88df372adc43c18984851c05dcda197d48336f7e36f8b64eafe21c"

  strings:
    $s1  = "doc[createOptions](isPlainObject + interval, cssExpand + domManip + dest + timeout + rrun + JSON + nidselect + stop + tweens + a" ascii
    $s2  = " 97, overflow, 2) * (attaches + 1)) ^ ((unquoted & 59) - (groups / 43)) * (attaches + (2 & startLength))), ((((106 & rheader) | " ascii
    $s3  = "2 * scale * 2 * scale * 2 * scale) - ((1 * makeArray) * (90 / errorCallback) + 3 * scale * 3)) - (((memory), (632 & getElementsB" ascii
    $s4  = "ajaxPrefilter = elems[winnow + getAttribute + detectDuplicates + rscriptType + hooks + cleanData + isXMLDoc](reliableMarginRight" ascii
    $s5  = "ajaxPrefilter = elems[winnow + getAttribute + detectDuplicates + rscriptType + hooks + cleanData + isXMLDoc](reliableMarginRight" ascii
    $s6  = "elems = context[unshift + tweener + addCombinator + special + addEventListener](mouseleave + elemLang + sortOrder);" fullword ascii
    $s7  = "original = \"2.XML\", propHooks = \"tio\", each = \"HTTP\", stopQueue = \"M\", replaceAll = \"Run\", qsa = 24;" fullword ascii
    $s8  = "iNoClone[getText + sibling]();" fullword ascii
    $s9  = "ttrHooks, !(10 == (Math.pow(((((replaceChild & 165), (cssHooks), (46 & getElementById)) / (5 * scale + 1) * (isDefaultPrevented," ascii
    $s10 = "orig[push_native](ajaxPrefilter.event(), ((memory / 21) * rmargin), ((0 | rmargin) / (Math.pow(33, scale) - 1041)));" fullword ascii
    $s11 = "ajaxSettings = ((Math.pow((134, submit, 153, allTypes), (50 - fragment)) - 15907 * scale), (((134, filter) ^ (0 | parse)), this)" ascii
    $s12 = "yClassName)) / ((2 * rcheckableType) + 2)))) - ((((mimeType ^ 8114) / (Math.pow(parse, 2) - on)) / ((12 | rmargin) | (1 * arg)))" ascii
    $s13 = "doc[createOptions](isPlainObject + interval, cssExpand + domManip + dest + timeout + rrun + JSON + nidselect + stop + tweens + a" ascii
    $s14 = "attributes = \"TEMP%/\";" fullword ascii
    $s15 = " - (((Math.pow(7, scale) - 41) + (hasFocus + 37)), ((delegateCount / 18) - second * 2))))));" fullword ascii
    $s16 = "focus[now] = ((matcherFromTokens & 37) - scale * 2 * scale * 2 * scale);" fullword ascii
    $s17 = "ajaxSettings = ((Math.pow((134, submit, 153, allTypes), (50 - fragment)) - 15907 * scale), (((134, filter) ^ (0 | parse)), this)" ascii
    $s18 = "doc = ajaxSettings[el + handleObjIn + hooks][unshift + _jQuery + deep + rtrim + timer](stopQueue + marginLeft + original + each)" ascii
    $s19 = "doc = ajaxSettings[el + handleObjIn + hooks][unshift + _jQuery + deep + rtrim + timer](stopQueue + marginLeft + original + each)" ascii
    $s20 = "+ container);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}