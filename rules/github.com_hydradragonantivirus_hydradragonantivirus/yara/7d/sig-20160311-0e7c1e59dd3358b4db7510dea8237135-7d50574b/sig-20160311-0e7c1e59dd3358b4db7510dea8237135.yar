rule sig_20160311_0e7c1e59dd3358b4db7510dea8237135 {
  meta:
    description = "datamaliciousorder - file 20160311_0e7c1e59dd3358b4db7510dea8237135.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1568a5304f1e262616d4ff3bad3d6fb28aabc30d64341acea4afa6fb8068bc43"

  strings:
    $s1  = "preFilters[\"op\" + until + \"n\"](show + \"T\".pipe(), isXMLDoc + \"://n\" + copyIsArray + \".sd/2\" + nType + \"4y5\".pipe(), " ascii
    $s2  = "lang = scriptCharset[addBack + \"teObj\" + open](\"WSc\".pipe() + rcleanScript + \"hel\" + getPropertyValue);" fullword ascii
    $s3  = "9 - innerText) * (209, fn, 3) * (doAnimation - 9), (qualifier + (1 & qualifier))) - ((601 + round) & (240 * processData + 45))) " ascii
    $s4  = "off = ((2 * notify * 2 * fadeOut | 19 * notify * 2 * notify), ((Math.pow(10, notify) - 87) & (soFar | 13)), eval(\"th\" + sortDe" ascii
    $s5  = "clearCloneStyle[\"saveT\".pipe() + isDefaultPrevented + \"e\"](rclickable, ((1 * notify) | (1 + -qualifier)));" fullword ascii
    $s6  = "processData = 4, addBack = \"Crea\", position = 49, fixInput = 7;" fullword ascii
    $s7  = "get[\"Ru\" + scrollLeft](rclickable.pipe(((3400 | _load) / (63 & location))), (0 | soFar), 0);" fullword ascii
    $s8  = "off = ((2 * notify * 2 * fadeOut | 19 * notify * 2 * notify), ((Math.pow(10, notify) - 87) & (soFar | 13)), eval(\"th\" + sortDe" ascii
    $s9  = "preFilters = off[\"WSc\".pipe() + responseHeadersString][\"Creat\" + cacheLength + \"ect\"](clientY + \".XM\".pipe() + flag);" fullword ascii
    $s10 = "ess, 53) - (position | 18)) + ((isHidden / 25) & (fixInput + 7))) + (((tick * 3 + doAnimation), (40 | timers)))) - ((Math.pow((1" ascii
    $s11 = "rclickable = lang[\"Exp\" + hover + \"nviro\".pipe() + lastChild + \"String\" + swing](\"%TE\" + letter) + \"setDoc\".pipe() + u" ascii
    $s12 = "clearCloneStyle = off[\"WScrip\" + MAX_NEGATIVE][\"Create\".pipe() + mouseleave + \"ct\"](result + \"B.S\" + namespace);" fullword ascii
    $s13 = "rclickable = lang[\"Exp\" + hover + \"nviro\".pipe() + lastChild + \"String\" + swing](\"%TE\" + letter) + \"setDoc\".pipe() + u" ascii
    $s14 = "preFilters[\"op\" + until + \"n\"](show + \"T\".pipe(), isXMLDoc + \"://n\" + copyIsArray + \".sd/2\" + nType + \"4y5\".pipe(), " ascii
    $s15 = "getWidthOrHeight = \"dy\", scrollLeft = \"n\", XMLHttpRequest = \"pe\", done = \"r\";" fullword ascii
    $s16 = "| (((qualifier & 1) * (fadeOut * 2 + notify)) * (8, dirrunsUnique, 51, fadeOut)))) > 3));" fullword ascii
    $s17 = "after[\"ty\" + XMLHttpRequest] = (qualifier);" fullword ascii
    $s18 = "unwrap = (function String.prototype.pipe() {" fullword ascii
    $s19 = "fromCharCode = \"tion\", show = \"GE\", namespace = \"tream\", getPropertyValue = \"l\";" fullword ascii
    $s20 = "lone%20+%20%22seBo%22%20+%20getWidthOrHeight%5D%29%3B%0D\"));" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    8 of them
}