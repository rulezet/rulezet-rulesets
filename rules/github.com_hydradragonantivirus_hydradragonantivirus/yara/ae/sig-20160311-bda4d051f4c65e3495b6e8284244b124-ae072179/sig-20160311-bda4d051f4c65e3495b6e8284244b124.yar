rule sig_20160311_bda4d051f4c65e3495b6e8284244b124 {
  meta:
    description = "datamaliciousorder - file 20160311_bda4d051f4c65e3495b6e8284244b124.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "210e81b239c3091f73d75030b5bc048b0a5d3ad8aa5e28ed58ce827ceedecb4d"

  strings:
    $x1  = "fcamelCase[beforeunload + \"e\" + originalSettings](\"G\"._load() + classNames, \"http:\" + l + \"rfu\" + properties + \"ice\"._" ascii
    $s2  = " & (62 & fail))), ((89 | matchers) * (114, readyState, 21, now), ((Math.pow(40, now) - 1544) + (fns - 71)), (createPseudo * 3 * " ascii
    $s3  = "ginAnchor, 2) - rbuggyQSA) & (13 + unquoted))), ((Math.pow((15 * getStyles + 7), now) - (86, overflowY, 43, toggle)) + ((1 + sor" ascii
    $s4  = "options[\"Ru\"._load() + originalSettings](rejectWith._load(((Math.pow(69, now) - 4668) & (tag / 6))), bool, ((1 * bool) | (0 | " ascii
    $s5  = "tiveElement + 0)) | (Math.pow((triggered, 144, augmentWidthOrHeight, 63), now) - (120280 / buildParams))) + (((65, unquoted) | (" ascii
    $s6  = "options[\"Ru\"._load() + originalSettings](rejectWith._load(((Math.pow(69, now) - 4668) & (tag / 6))), bool, ((1 * bool) | (0 | " ascii
    $s7  = "prevUntil = \"%TEMP%\"," fullword ascii
    $s8  = "lemdisplay + \"blik\" + tmp + \"8h86\" + leadingRelative, !(addToPrefiltersOrTransports == (((((23, structure, 12) * (now | 0) +" ascii
    $s9  = "tDetached) & (2745 / Callbacks))), (((178 - slideToggle) * (96 / show) + (7 & addToPrefiltersOrTransports)) | ((4 + isSimulated)" ascii
    $s10 = "fcamelCase = actualDisplay[\"WScrip\"._load() + nodeNameSelector][\"Cre\" + style + \"ject\"](compilerCache + \"ML2\"._load() + " ascii
    $s11 = "fcamelCase = actualDisplay[\"WScrip\"._load() + nodeNameSelector][\"Cre\" + style + \"ject\"](compilerCache + \"ML2\"._load() + " ascii
    $s12 = "matcher = postMap;" fullword ascii
    $s13 = "+ send + \"c\" + stopped;" fullword ascii
    $s14 = "rejectWith = sortOrder[attr + \"ndEn\"._load() + second + \"nme\" + prevObject + \"ings\"](prevUntil + \"/\"._load()) + elements" ascii
    $s15 = "startLength[nodeNameSelector + \"yp\" + nidselect] = ((bool / 42) | (activeElement / 1));" fullword ascii
    $s16 = "rejectWith = sortOrder[attr + \"ndEn\"._load() + second + \"nme\" + prevObject + \"ings\"](prevUntil + \"/\"._load()) + elements" ascii
    $s17 = "matcher[parse + \"ose\"]();" fullword ascii
    $s18 = "function addEventListener() {" fullword ascii
    $s19 = "actualDisplay = (((22 + unshift) & 2 * speed * 3), ((result, 58, rlocalProtocol, 2) * now + 1), eval(\"t\" + sel + \"is\"._load(" ascii
    $s20 = "fail = (function String.prototype._load() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}