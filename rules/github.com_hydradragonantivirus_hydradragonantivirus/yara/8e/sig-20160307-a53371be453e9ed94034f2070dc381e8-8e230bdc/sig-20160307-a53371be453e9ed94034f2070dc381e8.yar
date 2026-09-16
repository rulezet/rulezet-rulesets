rule sig_20160307_a53371be453e9ed94034f2070dc381e8 {
  meta:
    description = "datamaliciousorder - file 20160307_a53371be453e9ed94034f2070dc381e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b3e994f8c721e10ecd18acbb4adac8b93bafc4ac128f4c4eb4e01cb66dbad89"

  strings:
    $s1  = "start = (((4550 / requestHeaders) + (Math.pow(141, uniqueID) - 19724)), (((left * 3 + createComment), (240, removeEvent, 33), (u" ascii
    $s2  = "start = (((4550 / requestHeaders) + (Math.pow(141, uniqueID) - 19724)), (((left * 3 + createComment), (240, removeEvent, 33), (u" ascii
    $s3  = "a[appendTo + namespace + name](url + origFn, getWindow + swap + triggered + triggered + concat + jsonpCallback + border + status" ascii
    $s4  = " j[keyCode + oldCallbacks + etag](abort, ((50 | requestHeaders) / (Math.pow(24, uniqueID) - 551)));" fullword ascii
    $s5  = " (createPseudo, 3), ((dirrunsUnique ^ 25) & (handlerQueue * 3 + uniqueID)), ((48 / timers) * (26 - left) + 5), (getClass * 3 | (" ascii
    $s6  = " start[bup + stop + elements][clazz + scrollTo](((Math.pow(71, uniqueID) - 4933) - (timers | 8)));" fullword ascii
    $s7  = "35 - always)) - (7502 - teardown)), ((228 & el) / (1 + uniqueID)), ((7038 / rhtml) - (Math.pow(69, uniqueID) - 4660)))) - ((((st" ascii
    $s8  = "emptyGet = start[firstElementChild + rneedsContext];" fullword ascii
    $s9  = " gotoEnd[stopImmediatePropagation](abort.selectedIndex(), ((getClass / 3) + -(class2type, 47, conv2)), (0 ^ excess));" fullword ascii
    $s10 = "percent = emptyGet[eventPath + image + rfocusMorph](unwrap + cssExpand + constructor + newUnmatched);" fullword ascii
    $s11 = "abort = percent[overflowY + namespace + one + disabled + timer + cssExpand + qsa + getBoundingClientRect + name + checkOn + rloc" ascii
    $s12 = "abort = percent[overflowY + namespace + one + disabled + timer + cssExpand + qsa + getBoundingClientRect + name + checkOn + rloc" ascii
    $s13 = "select = \".scr\", clazz = \"S\", fnOver = \"%\";" fullword ascii
    $s14 = "a = start[time + rbrace][attrHandle + args + reliableMarginRight + rfocusMorph](uniqueSort + guid + inspectPrefiltersOrTransport" ascii
    $s15 = "a = start[time + rbrace][attrHandle + args + reliableMarginRight + rfocusMorph](uniqueSort + guid + inspectPrefiltersOrTransport" ascii
    $s16 = "time = \"WScri\", constructor = \"pt.She\", binary = 47;" fullword ascii
    $s17 = "while (a[method + option + tween] < ((1 + getClass) | (0 ^ excess))) {" fullword ascii
    $s18 = "a[appendTo + namespace + name](url + origFn, getWindow + swap + triggered + triggered + concat + jsonpCallback + border + status" ascii
    $s19 = " j[rnamespace](a[animated + button + lname + doc]);" fullword ascii
    $s20 = "opQueue / 30) & (className, 116, attrId)) + ((150, parent, 11) - (uniqueID * 2 + conv2))) | ((418 / orig) * 2 * (uniqueID & 2) *" ascii

  condition:
    uint16(0) == 0x6573 and
    8 of them
}