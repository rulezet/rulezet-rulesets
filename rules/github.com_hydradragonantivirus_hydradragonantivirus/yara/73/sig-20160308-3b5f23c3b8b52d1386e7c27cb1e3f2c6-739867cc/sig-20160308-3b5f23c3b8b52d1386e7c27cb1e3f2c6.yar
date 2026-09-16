rule sig_20160308_3b5f23c3b8b52d1386e7c27cb1e3f2c6 {
  meta:
    description = "datamaliciousorder - file 20160308_3b5f23c3b8b52d1386e7c27cb1e3f2c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24c69acf765d7c69c72e33387a5a01c4d7748cdce7ebaeff159211ebcec54d32"

  strings:
    $s1  = "stopped[elementMatchers](pdataCur, abort + preFilters + toSelector + winnow + append + timer + stopQueue + seed + attr + groups " ascii
    $s2  = "owner = (((Math.pow(56, manipulationTarget) - 3072) | (Math.pow(prevObject, 2) - dest)), ((624 / grep), this));" fullword ascii
    $s3  = "pedTypes)), (2 & callbackExpect)) - (73 - pageX) * (Math.pow(69, manipulationTarget) - 4690))), ((((traditional * 4 + params) / " ascii
    $s4  = "+ state + assert + until, !(7 == ((((mappedTypes * 3 * matchesSelector * 3 / (fromCharCode + 2)) / (Math.pow((manipulationTarget" ascii
    $s5  = "onTarget) - 2707)) ^ (Math.pow((getClass - 29), (close ^ 2)) - (docElem, 172, animated))) | (Math.pow(((35 & checkOn) ^ (1 + map" ascii
    $s6  = "compile[mouseenter](promise.fns(), ((replaceChild + -1) / (defaultExtra & 55)), ((replaceChild + 0) + -(replaceChild | 1)));" fullword ascii
    $s7  = "owner[suffix + bp][param + noop](((238875 / getWidthOrHeight) ^ (6925 - nextAll)));" fullword ascii
    $s8  = "(4 * callbackExpect + 1)) ^ ((rtypenamespace / 17) + (pipe ^ 73))) / ((Math.pow((jqXHR / 9), (replaceChild + 1)) - (backgroundCl" ascii
    $s9  = " * 12), (close | 2)) - (Math.pow(vendorPropName, 2) - pageYOffset))) * (Math.pow(((30 - params) ^ (Math.pow(7, manipulationTarge" ascii
    $s10 = "while (stopped[responseContainer + pointerleave + keys] < ((transports, 24) - (after * 4))) {" fullword ascii
    $s11 = "t) - 38)), (replaceChild ^ 3)) - ((dataType & 127), (handlers, 64, collection))) + ((1 + (replaceChild & 1)) | ((replaceChild | " ascii
    $s12 = "ip - 10)), ((fix + 24) | (special / 8)), ((clearQueue - 169), (simple + 24)))))));" fullword ascii
    $s13 = " (after - 3)));" fullword ascii
    $s14 = "msMatchesSelector[flag + completeDeferred + matcherOut + nType](promise, ((extend ^ 145), (callbackExpect * 4), (andSelf & 252)," ascii
    $s15 = "unbind = owner[rts + tick + box + preFilters];" fullword ascii
    $s16 = "namespace = unbind[pixelPosition + preFilters + sel + completed](adown + success + triggerHandler);" fullword ascii
    $s17 = "var pipe = 49;" fullword ascii
    $s18 = "stopped[elementMatchers](pdataCur, abort + preFilters + toSelector + winnow + append + timer + stopQueue + seed + attr + groups " ascii
    $s19 = "agment + animate + offset + writable + overflow);" fullword ascii
    $s20 = " attr + eventHandle + finish + deep + setPositiveNumber);" fullword ascii

  condition:
    uint16(0) == 0x6973 and
    8 of them
}