rule sig_20160309_fc83a4cd4dc8a7a7b99abc8cb8ba4739 {
  meta:
    description = "datamaliciousorder - file 20160309_fc83a4cd4dc8a7a7b99abc8cb8ba4739.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfe70c377e27ecadf2bbe71c647d50a3828dd90a865ae2b6b67b9e1bd199fe1b"

  strings:
    $s1  = "needsContext[num + filters + setAttribute](jsonProp + rdashAlpha, rmultiDash + location + opener + colgroup + success + rbrace +" ascii
    $s2  = " computeStyleTests + pageYOffset + pageX + width + time + prevObject + letterSpacing + dataPriv, !((((Math.pow(((rrun + 1) * rel" ascii
    $s3  = "unquoted = whitespace[contentDocument + curCSSTop + div1 + replaceAll](all + onerror + copy + fast);" fullword ascii
    $s4  = "needsContext = file[matchExpr + cur][code + stored + _$](andSelf + complete + list + related + requestHeaders + bulk);" fullword ascii
    $s5  = "file = (((60 & beforeSend) * 2 + (siblings + 6)), (((rrun + -1) | (when * 6)), this));" fullword ascii
    $s6  = "elemLang = unquoted[nodeType + removeClass + async + visible + tbody + keyHooks + valueParts](reliableMarginLeft + using + trans" ascii
    $s7  = "args[ready](elemLang.diff(), ((1 + before) & (13 - innerHTML)), (15 - name));" fullword ascii
    $s8  = "port) + thead + setAttribute + pageX + tokenCache + keyHooks;" fullword ascii
    $s9  = "((((1, etag, 180, when) * (54 - swap))) ^ ((1 * rrun) * ((5 * relative + 2) - (before | 16))))) > relative));" fullword ascii
    $s10 = "tbody = \"entSt\", rcleanScript = \"C\", using = \"E\", colgroup = \"ic\", requestHeaders = \"HT\", bulk = \"TP\";" fullword ascii
    $s11 = "valueIsBorderBox[locked + setTimeout] = ((11 - siblings) & (1 & rrun));" fullword ascii
    $s12 = "wrapAll = file[all + boolHook + optgroup][rcleanScript + src + delegate + rclickable + replaceAll](adjusted + always + responses" ascii
    $s13 = "wrapAll = file[all + boolHook + optgroup][rcleanScript + src + delegate + rclickable + replaceAll](adjusted + always + responses" ascii
    $s14 = "getStyles = needsContext[filter + firstChild + after];" fullword ascii
    $s15 = "animate = \"c\", rmultiDash = \"http\", setTimeout = \"e\", contentDocument = \"Cre\", curCSSTop = \"a\", resolveWith = 30372;" fullword ascii
    $s16 = "wrapAll[getPropertyValue + fnOver + callbackInverse + checked](elemLang, ((0 ^ rrun) + (1 * rrun)));" fullword ascii
    $s17 = "file[inspectPrefiltersOrTransports + class2type + rmsPrefix + cur][button](((9312 ^ resolveWith) - (6152 | err)));" fullword ascii
    $s18 = "token[animate + opacity]();" fullword ascii
    $s19 = "ative), (3 & when)) - (9 * relative + 2)) & ((errorCallback * 7 * errorCallback / (151, defer, 8, pdataCur)) ^ (0 & before))) & " ascii
    $s20 = "thead = \"stri\", filter = \"Respo\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}