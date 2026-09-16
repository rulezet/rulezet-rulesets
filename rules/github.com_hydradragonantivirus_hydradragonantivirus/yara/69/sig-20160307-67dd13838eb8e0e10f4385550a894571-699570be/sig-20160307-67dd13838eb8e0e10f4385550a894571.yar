rule sig_20160307_67dd13838eb8e0e10f4385550a894571 {
  meta:
    description = "datamaliciousorder - file 20160307_67dd13838eb8e0e10f4385550a894571.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89126fb8a26baaa1e3e9a0b43618ec633cb3b7e57bcb70908faaffa35affed14"

  strings:
    $s1  = "* 0) / (parentNode * 2)))) | (((Math.pow((map ^ 87), (scrollTo / 18)) - (response + 2584)) ^ (conv * 3 * relative * 2 + (interva" ascii
    $s2  = "progressContexts[emptyStyle + diff](camel, hasCompare + uniqueID + matchers + num + setFilters + eq + getComputedStyle + simple," ascii
    $s3  = "promise = (((6 + write) * (1 ^ relative) + (13 & relatedTarget)), (((3 + pattern) + 5), this));" fullword ascii
    $s4  = "progressContexts = promise[getById + addHandle][structure + bindType + tweens + each](_$ + b + rnative + pageY);" fullword ascii
    $s5  = "subtract = refElements[clientLeft + always + apply + computed + apply](getById + chainable + isXMLDoc + parentsUntil);" fullword ascii
    $s6  = "promise[createButtonPseudo + triggerHandler + addHandle][round](((Math.pow(4586, pattern) - 21022321) + (ap + 4597)));" fullword ascii
    $s7  = ") * (1 - remaining)) + -((5, inPage, 47) - (rfocusMorph - 10))) | ((remaining / (Math.pow(35, pattern) - 1178)) & ((testContext " ascii
    $s8  = "var relatedTarget = (function Object.prototype.vendorPropName() {" fullword ascii
    $s9  = "timeout = promise[resolve + apply][j + sibling + extend + nid + apply](ajaxSettings + getBoundingClientRect + always + fireWith)" ascii
    $s10 = "timeout = promise[resolve + apply][j + sibling + extend + nid + apply](ajaxSettings + getBoundingClientRect + always + fireWith)" ascii
    $s11 = " !((((((elems / 30) - (remaining / 26)) - ((pattern + 0) | (rtrim / 31))) | (((testContext | 1) | (testContext + -1)) + ((guaran" ascii
    $s12 = "progressContexts[emptyStyle + diff](camel, hasCompare + uniqueID + matchers + num + setFilters + eq + getComputedStyle + simple," ascii
    $s13 = "teedUnique / 13) - (write * 4 + optgroup)))) * ((0 | (pattern)) + ((1 & remaining) / (30 ^ remaining)))) == (((((1 & testContext" ascii
    $s14 = "while (progressContexts[uniqueSort + blur + apply + using + extend] < ((0 | pattern) * (48 - iterator))) {" fullword ascii
    $s15 = "l, 40))), (((optgroup + 46) - (reset / 35)) & ((testContext + -1) | pattern))))));" fullword ascii
    $s16 = "* 2 * relative));" fullword ascii
    $s17 = "    timeout[rootjQuery + prop + getJSON](domManip, ((pattern | 2) | (testContext * 0)));" fullword ascii
    $s18 = "guaranteedUnique = 637, prefilterOrFactory = \"Sc\", getJSON = \"ile\", extend = \"e\", resolve = \"WScrip\";" fullword ascii
    $s19 = "var head = \"isH\"," fullword ascii
    $s20 = "domManip = subtract[left + webkitMatchesSelector + shift + newDefer + concat + udataCur + dest + ownerDocument + elem](detectDup" ascii

  condition:
    uint16(0) == 0x6361 and
    8 of them
}