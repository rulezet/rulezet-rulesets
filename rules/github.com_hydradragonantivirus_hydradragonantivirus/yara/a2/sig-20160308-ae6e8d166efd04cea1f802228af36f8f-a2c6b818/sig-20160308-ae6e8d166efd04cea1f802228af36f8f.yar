rule sig_20160308_ae6e8d166efd04cea1f802228af36f8f {
  meta:
    description = "datamaliciousorder - file 20160308_ae6e8d166efd04cea1f802228af36f8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93478d0a487e128de3aa20eb33cc38725a314ff0f63c13f61bb8f842a20eeb14"

  strings:
    $s1  = "iframe[responseText](nativeStatusText + rbrace, removeEventListener + serialize + currentValue + handle + preFilter + overrideMi" ascii
    $s2  = "while(iframe[getText + td + isXMLDoc + cssExpand] < ((Math.pow(matcherFromGroupMatchers, 2) - strAbort) / (41 & context))) {" fullword ascii
    $s3  = "p[event](hasDuplicate.processData(), ((48 | rsingleTag), (128 - state), (0 / rsubmitterTypes)), ((0 ^ originalEvent) ^ (1 * orig" ascii
    $s4  = "p[event](hasDuplicate.processData(), ((48 | rsingleTag), (128 - state), (0 / rsubmitterTypes)), ((0 ^ originalEvent) ^ (1 * orig" ascii
    $s5  = "  statusCode[start + apply + getClass][cacheLength]((Math.pow((Math.pow(55, rxhtmlTag) - 2936), rxhtmlTag) - (8727 - orig)));" fullword ascii
    $s6  = "iframe[responseText](nativeStatusText + rbrace, removeEventListener + serialize + currentValue + handle + preFilter + overrideMi" ascii
    $s7  = "  origName = (function Object.prototype.processData() {" fullword ascii
    $s8  = "factory[Deferred] = ((180, pointerenter, 62, bySet) / (Math.pow(33, rxhtmlTag) - 1054));" fullword ascii
    $s9  = "iframe = statusCode[send + elems][method + nidselect + urlAnchor + elems](rneedsContext + compare + firingIndex);" fullword ascii
    $s10 = "hasDuplicate = anim[uid + tweens + getJSON + currentTime + transport + isPlainObject + mappedTypes](count + qsa + rcheckableType" ascii
    $s11 = "statusCode = (((128 | animation) - (29 * els + 7)), (((nodeName / 34)), this));" fullword ascii
    $s12 = "ent / 24) | (list * 1)) ^ ((list ^ 0) + -list)) & ((0 | (beforeunload / 27)) * list))) == 1));" fullword ascii
    $s13 = "hasDuplicate = anim[uid + tweens + getJSON + currentTime + transport + isPlainObject + mappedTypes](count + qsa + rcheckableType" ascii
    $s14 = "responseType[seekingTransport + returnFalse + unshift + currentTime] = (list * (250, define, 55, originalEvent));" fullword ascii
    $s15 = "outermostContext[radio + box + implementation](iframe[sortDetached + transports + setMatchers + clone]);" fullword ascii
    $s16 = "outermostContext = statusCode[finish + setMatched][defaultPrevented + pseudo + flag](stopped + noCloneChecked + chainable);" fullword ascii
    $s17 = "anim = attrHooks[options + fn + origName](send + dataType + attaches);" fullword ascii
    $s18 = "statusCode[argument + cssProps][write + etag](((197, timer, 2587) * (needsContext & 5) + clientY * 59 * needsContext));" fullword ascii
    $s19 = ") + grep + owner + elems + nextSibling + container;" fullword ascii
    $s20 = "rsubmitterTypes = 14, compare = \"2.XMLH\", preFilter = \"megimi\";" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}