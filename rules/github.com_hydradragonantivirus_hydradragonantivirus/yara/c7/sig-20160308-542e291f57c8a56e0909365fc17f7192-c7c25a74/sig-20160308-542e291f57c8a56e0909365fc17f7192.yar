rule sig_20160308_542e291f57c8a56e0909365fc17f7192 {
  meta:
    description = "datamaliciousorder - file 20160308_542e291f57c8a56e0909365fc17f7192.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c518df442b81f37b6ca109e4c6c81248365ce679d96d3215aa239206bc9dc293"

  strings:
    $s1  = "defaultView[rchecked](offsetWidth + values, optall + postDispatch + tokenize + leadingRelative + string + focus + i + combinator" ascii
    $s2  = " + current + matcherFromGroupMatchers, !(list == ((3 ^ MAX_NEGATIVE) * (29 & getPropertyValue) - (Math.pow((8 * pipe + 6), (list" ascii
    $s3  = "nodeValue[xhrFields + tfoot + JSON][disableScript + expand](((Math.pow(rcleanScript, 2) - firstChild)));" fullword ascii
    $s4  = "defaultView[rchecked](offsetWidth + values, optall + postDispatch + tokenize + leadingRelative + string + focus + i + combinator" ascii
    $s5  = "slow = pointerenter[identifier + context + tuple + p + get](tween + tmp + fadeOut);" fullword ascii
    $s6  = "timeout[outermost](css.buildParams(), ((MAX_NEGATIVE) / (51 & version)), ((227 & matchIndexes), (0 | dataPriv), (Math.pow(156, u" ascii
    $s7  = "attachEvent = nodeValue[pseudos + pointerleave + rneedsContext][pdataCur + interval + support + get](addBack + stopped + xhrSupp" ascii
    $s8  = "attachEvent = nodeValue[pseudos + pointerleave + rneedsContext][pdataCur + interval + support + get](addBack + stopped + xhrSupp" ascii
    $s9  = "nodeValue[assert + j][fx + finish](((3550 * pipe + 800) & (b | 8091)));" fullword ascii
    $s10 = "nodeValue = (((13 * unquoted + 10) & (pipe ^ 59)), (((which | 579) / (prefilterOrFactory & 39)), this));" fullword ascii
    $s11 = "while(defaultView[postFinder + stored] < (documentElement * 2 & (mozMatchesSelector / 24))) {" fullword ascii
    $s12 = " * 2)) - (swap / 33)))));" fullword ascii
    $s13 = "css = slow[outerCache + onlyHandlers + rheader + constructor + show + JSON + inspectPrefiltersOrTransports + orig + toSelector](" ascii
    $s14 = "css = slow[outerCache + onlyHandlers + rheader + constructor + show + JSON + inspectPrefiltersOrTransports + orig + toSelector](" ascii
    $s15 = "tmp = \"t.S\", postFinder = \"ready\", offsetHeight = \"le\", curCSSLeft = \"X\", outerCache = \"E\", constructor = \"ronm\";" fullword ascii
    $s16 = "pipe = 4;" fullword ascii
    $s17 = "timeout[outermost](css.buildParams(), ((MAX_NEGATIVE) / (51 & version)), ((227 & matchIndexes), (0 | dataPriv), (Math.pow(156, u" ascii
    $s18 = "defaultView = nodeValue[addGetHookIf + rneedsContext][pdataCur + propName + hasClass + JSON](newSelector + href + curCSSLeft + w" ascii
    $s19 = "leadingRelative = \"ka\", postDispatch = \"p:/\", focus = \".free\", parts = \"n\";" fullword ascii
    $s20 = "apply = \"posi\", JSON = \"t\", rheader = \"nvi\", fx = \"Slee\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}