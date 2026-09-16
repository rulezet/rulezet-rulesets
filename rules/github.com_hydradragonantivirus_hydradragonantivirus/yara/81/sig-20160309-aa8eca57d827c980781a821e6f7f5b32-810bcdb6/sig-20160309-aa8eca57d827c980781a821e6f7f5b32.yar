rule sig_20160309_aa8eca57d827c980781a821e6f7f5b32 {
  meta:
    description = "datamaliciousorder - file 20160309_aa8eca57d827c980781a821e6f7f5b32.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e66c0fcdda4e6fae688a777b49bfeb41667a7d77cf8b87e7b58a0bc1b79a67e8"

  strings:
    $s1  = "ajax[diff + firing](clearTimeout + manipulationTarget, tick + addClass + valueIsBorderBox + rejectWith + isFunction + updateFunc" ascii
    $s2  = "run[iterator + isEmptyObject + hasContent + offset + isHidden](source, ((1 * propFix) - (35 - merge)));" fullword ascii
    $s3  = "source = emptyGet[matcherFromTokens + support + username + throws + rmargin + doneName + firing + state + each](createHTMLDocume" ascii
    $s4  = "source = emptyGet[matcherFromTokens + support + username + throws + rmargin + doneName + firing + state + each](createHTMLDocume" ascii
    $s5  = "th.pow(2644, divStyle) - 6987306) - (getElementsByClassName * 6 + optDisabled))) / (((23 * divStyle + 9) & (propFix * 5 + status" ascii
    $s6  = "th[el](source.isArrayLike(), (mozMatchesSelector ^ 0), ((dataPriv + -1) / bind * 3));" fullword ascii
    $s7  = " + nid + rhtml + charCode + initial, !(divStyle < ((((Math.pow((74028 / showHide), (1 ^ rfocusable)) - (4331648 | using)) | ((Ma" ascii
    $s8  = "ajax[diff + firing](clearTimeout + manipulationTarget, tick + addClass + valueIsBorderBox + rejectWith + isFunction + updateFunc" ascii
    $s9  = "scrollLeft[_$ + Symbol + getById][progressContexts + defaultExtra]((29 * divStyle * 17 * propFix ^ 7 * divStyle * 593));" fullword ascii
    $s10 = "scrollLeft = ((2 * divStyle * 2 * rfocusable * 2 * divStyle * 2 * divStyle / (11 + queue)), ((1 * (related - 45)), this));" fullword ascii
    $s11 = "uggyQSA - 46)) * ((showHide * 2 + statusText) / (451 / string)) + ((1 ^ divStyle) & (2 | rfocusable))) + ((1 * mozMatchesSelecto" ascii
    $s12 = "r) | ((50 & sort) - (56 - propFix)))))));" fullword ascii
    $s13 = "getStyles = \"je\", support = \"xpa\", trigger = \"/\", handleObj = \"ript\", fast = \"Ob\";" fullword ascii
    $s14 = "Text)) + (3 ^ mozMatchesSelector))) - ((((1 | dataPriv) * (18 - setPositiveNumber)) * 2) * ((divStyle * 3 * rfocusable * 2 / (rb" ascii
    $s15 = "run = scrollLeft[startLength + handleObj][animation + fast + getStyles + curOffset](speeds + callback + sortInput + src);" fullword ascii
    $s16 = "emptyGet = orig[tweeners + newCache + matchAnyContext](position + timeStamp + escapedWhitespace + timer);" fullword ascii
    $s17 = "related = 48, contentType = \"clo\", rbracket = \"i\", hasData = \"rite\", sourceIndex = \"t\", showHide = 31;" fullword ascii
    $s18 = "ajax = scrollLeft[fixInput + type][rtypenamespace + defaultValue + curOffset](pop + rneedsContext + tbody + wait + handle);" fullword ascii
    $s19 = "nt + fadeIn + trigger) + prepend + timer + height + which + margin + pdataOld;" fullword ascii
    $s20 = "rclickable = ajax[isWindow + file + qualifier];" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}