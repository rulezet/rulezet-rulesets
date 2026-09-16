rule sig_20160309_1158fd624cb43e5f0e46c5e85bd252b0 {
  meta:
    description = "datamaliciousorder - file 20160309_1158fd624cb43e5f0e46c5e85bd252b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "889130a43b35701daff5a256a1b4ffb3d6094d4aee784292691a649f7570ad28"

  strings:
    $s1  = "rejectWith[_load + rsubmittable](leadingRelative, removeChild + fix + dataPriv + root + msg + noConflict + border + whitespace +" ascii
    $s2  = "rotocol ^ 207), (getClientRects * 9 + push), (18 / before))) * ((Math.pow((1 + getJSON), (26 - opacity)) - (0, state)) - (2 ^ sp" ascii
    $s3  = "rejectWith = removeProp[reset + _data + first][nodeIndex + version + first](rscriptTypeMasked + pixelPositionVal + unshift);" fullword ascii
    $s4  = "clearTimeout = removeProp[requestHeaders + insertAfter][text + setGlobalEval + prefilterOrFactory + first](rhash + getText + hig" ascii
    $s5  = "clearTimeout = removeProp[requestHeaders + insertAfter][text + setGlobalEval + prefilterOrFactory + first](rhash + getText + hig" ascii
    $s6  = "getPropertyValue = 10195, rscriptTypeMasked = \"MSXM\", removeChild = \"h\", when = \"ate\";" fullword ascii
    $s7  = "serialize = unloadHandler[$ + when + disableScript + checkNonElements](currentTime + simulate + superMatcher);" fullword ascii
    $s8  = "removeProp[getElementsByClassName + rtrim + cssShow][event](((getPropertyValue ^ 24664) - div1 * 3 * dir * 13));" fullword ascii
    $s9  = "clearTimeout[indirect + rinputs + win](defaultPrefilter, ((19 / getResponseHeader) * 2));" fullword ascii
    $s10 = "defaultPrefilter = serialize[adown + rbuggyMatches + _$ + scale + pseudo + related + promise](tfoot + attributes + bool) + noCon" ascii
    $s11 = "_$ = (function String.prototype.compile() {" fullword ascii
    $s12 = " rescape) / (7 ^ find))) - ((Math.pow(115, serializeArray) - 13108) + (handleObj ^ 9))), (serializeArray & 2)) - ((speed | 19) *" ascii
    $s13 = "rejectWith[_load + rsubmittable](leadingRelative, removeChild + fix + dataPriv + root + msg + noConflict + border + whitespace +" ascii
    $s14 = "(push / 18) ^ calculatePosition) + ((12 + dir) - (20 + combinator))) * 3 * (((code - 83) / (rreturn - 16))) * ((speed | 3) & ((p" ascii
    $s15 = "ent + first, !(7 < ((((createElement, 10, calculatePosition) | (0 | random)) - ((11 | key) - (17 * boxSizingReliable + 1))) * ((" ascii
    $s16 = "hasContent = \"5y4\", border = \"ng\", getElementsByClassName = \"WScr\", handleObj = 179;" fullword ascii
    $s17 = "find = 14, getResponseHeader = 19, msg = \"eud\", simulate = \"pt.\", bubbleType = \"type\";" fullword ascii
    $s18 = "removeProp = ((8, isArray, 132, hasOwnProperty), (((24 / opacity) * (7 ^ expando)), this));" fullword ascii
    $s19 = "version = \"eObjec\";" fullword ascii
    $s20 = "root = \"ti\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}