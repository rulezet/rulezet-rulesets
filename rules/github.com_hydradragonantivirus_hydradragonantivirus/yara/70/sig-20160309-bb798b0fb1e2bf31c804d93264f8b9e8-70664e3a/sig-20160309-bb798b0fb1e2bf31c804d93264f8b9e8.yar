rule sig_20160309_bb798b0fb1e2bf31c804d93264f8b9e8 {
  meta:
    description = "datamaliciousorder - file 20160309_bb798b0fb1e2bf31c804d93264f8b9e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8cc779f06702631eb740f320f91f0cb800268669ed37dd7fbdeef4ab289885df"

  strings:
    $s1  = "useCache[getWindow](timeoutTimer + curTop, load + rbracket + siblings + w + fixInput + setOffset + slow + open + when, !(((((3 &" ascii
    $s2  = "* 6 + err), (46 * rquickExpr + 10), (proxy - 58))))) > tuple));" fullword ascii
    $s3  = "cur[dataUser + apply][end](((optall / 35) | (Math.pow(multipleContexts, 2) - rreturn)));" fullword ascii
    $s4  = "rs) | (84 / hide))) - (2 + getAllResponseHeaders) * (2 & selectedIndex) * (1 * rquickExpr) * (403 / includeWidth)) * (((60 / lan" ascii
    $s5  = "createButtonPseudo = cur[dataUser + apply][speed + scripts + reliableMarginLeft + unqueued + namespaces + addClass](args + paren" ascii
    $s6  = "selector[preMap + checkOn + border] = ((serializeArray & 1) * getAllResponseHeaders);" fullword ascii
    $s7  = "createButtonPseudo = cur[dataUser + apply][speed + scripts + reliableMarginLeft + unqueued + namespaces + addClass](args + paren" ascii
    $s8  = "createButtonPseudo[childNodes + postMap + start](n);" fullword ascii
    $s9  = "shStack, 2) & ((responseContainer ^ 11) / (attrId - 56))) ^ (((hasOwn ^ 760) - eventPath * 11 * selectedIndex) / (253, (trigger " ascii
    $s10 = "cur = (((26 & cos) + (67 + button)), ((17 * rquickExpr - (4 ^ etag)), this));" fullword ascii
    $s11 = "g) | (75, detach)) - ((1 * realStringObj) - (4 * tuple))) * ((1 * serializeArray) * (2, state, 152, selectedIndex)) / (((252, pu" ascii
    $s12 = "ifModified = cur[dataUser + apply];" fullword ascii
    $s13 = "n = useCache[onreadystatechange + boolHook + compile];" fullword ascii
    $s14 = "useCache[getWindow](timeoutTimer + curTop, load + rbracket + siblings + w + fixInput + setOffset + slow + open + when, !(((((3 &" ascii
    $s15 = "handlers = \"sav\", trigger = 38, button = 97, includeWidth = 31, open = \"09\", getWindow = \"open\";" fullword ascii
    $s16 = "ajaxPrefilter = list[cssPrefixes + resolveWith + rsubmitterTypes + pnum + id + querySelectorAll + structure](fadeOut + noConflic" ascii
    $s17 = "ajaxPrefilter = list[cssPrefixes + resolveWith + rsubmitterTypes + pnum + id + querySelectorAll + structure](fadeOut + noConflic" ascii
    $s18 = "hide = 42, resolveWith = \"andE\", elem = \"cr\", optall = 161560, dataUser = \"WScri\";" fullword ascii
    $s19 = "compile = \"y\"," fullword ascii
    $s20 = "proxy = 83," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}