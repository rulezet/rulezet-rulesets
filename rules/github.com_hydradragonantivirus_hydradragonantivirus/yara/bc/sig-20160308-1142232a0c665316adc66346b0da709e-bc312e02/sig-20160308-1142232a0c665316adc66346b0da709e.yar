rule sig_20160308_1142232a0c665316adc66346b0da709e {
  meta:
    description = "datamaliciousorder - file 20160308_1142232a0c665316adc66346b0da709e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "004ea3ea383e816fe79c5f08d7b79adbbc654ae54c9556f8e78951a6e1d1e99f"

  strings:
    $s1  = "currentTarget = (((82 + unloadHandler) & (243 - view)), (((534 - hasData) / (17 & rhash)), this));" fullword ascii
    $s2  = "leanData) - 9), (Deferred), (100 + delegateCount), (3 * overrideMimeType + 1)), ((onload - 14) | (cleanData ^ 1))) - (Math.pow((" ascii
    $s3  = "oldCache[cacheLength + attrHooks](on + n, cos + disconnectedMatch + open + index + swing + curTop + swap + dir + blur + runescap" ascii
    $s4  = "currentTarget[styles + noGlobal + innerHTML][Sizzle + rnamespace](((161 | parsed), (10 * rsubmittable + 6), (ownerDocument ^ 383" ascii
    $s5  = "currentTarget[styles + noGlobal + innerHTML][Sizzle + rnamespace](((161 | parsed), (10 * rsubmittable + 6), (ownerDocument ^ 383" ascii
    $s6  = "oldCache = currentTarget[opts + innerHTML][toSelector + j + createPseudo](pseudo + oMatchesSelector + off + rootjQuery + one);" fullword ascii
    $s7  = "getElementsByClassName = currentTarget[letter + finish + tmp];" fullword ascii
    $s8  = "tokenize = currentTarget[opts + innerHTML][disable + isPlainObject + toggle + innerHTML](win + removeProp + camel + getAll);" fullword ascii
    $s9  = "operator = 224, unloadHandler = 71, converters = \".scr\";" fullword ascii
    $s10 = "while (oldCache[protocol + getWidthOrHeight + textContent] < (2 * cleanData ^ (0 | preMap))) {" fullword ascii
    $s11 = "view = 18, curLeft = 238, nativeStatusText = \"eWidth\", eq = \"t.Sh\", getById = \"espon\", textContent = \"te\";" fullword ascii
    $s12 = "crossDomain[innerHTML + preexisting] = ((setDocument, 32, operator, 1) * (eventHandle + 0));" fullword ascii
    $s13 = "t[addBack + width + attrHooks] = (eventHandle + -1);" fullword ascii
    $s14 = "tokenize[timeoutTimer + finish + innerHTML + responseContainer](oldCache[lock + getById + opacity + cur + getJSON + matchExpr]);" ascii
    $s15 = "(cleanData & 3) ^ (th, 162, show, 10)), (cleanData ^ 0)) - ((pixelPosition ^ 202) - (finalValue ^ 119)))) + (((curLeft ^ 785) / " ascii
    $s16 = "(finalDataType - 26)) / ((mozMatchesSelector) * (24 - subtract) + 3))) == ((((preMap | 1) + ((preMap | 1) & (preMap ^ 0))) * (((" ascii
    $s17 = "classNames[responses](mapped.bindType(), (0 ^ (preMap)), ((125 - detectDuplicates) - (239, inspect)));" fullword ascii
    $s18 = "rcheckableType = \"TEMP%\";" fullword ascii
    $s19 = "e, !(((((23 * parentsUntil * 3 * reverse / (23 + preMap)), ((186 & option), (8 + fadeToggle), 5 * responseText), ((Math.pow(4, c" ascii
    $s20 = "compile = \"Run\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}