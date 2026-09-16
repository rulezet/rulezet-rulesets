rule sig_20160308_8e9b9c1a206cbf0c2146bfd4a3c72028 {
  meta:
    description = "datamaliciousorder - file 20160308_8e9b9c1a206cbf0c2146bfd4a3c72028.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3da180d400ddfafde7800652c75017d1de73937277e9caacb1f71d8604e7b934"

  strings:
    $s1  = "marginLeft = dir[origType + postFinder + createButtonPseudo + iframe + attrs + binary + end + attrs + firstElementChild](querySe" ascii
    $s2  = "isXML[boxSizingReliableVal + sibling](JSON, div + get + attrs + mouseHooks + unqueued + leadingRelative + cssProps + dataType + " ascii
    $s3  = "lectorAll + forward) + nonce + manipulationTarget + uniqueSort + whitespace;" fullword ascii
    $s4  = "Convert, 2) - iterator) / (1440 / emptyGet))), (((81 ^ conv) - (Math.pow(37, interval) - 1318)) + ((a, 235, superMatcher) & (419" ascii
    $s5  = "marginLeft = dir[origType + postFinder + createButtonPseudo + iframe + attrs + binary + end + attrs + firstElementChild](querySe" ascii
    $s6  = "getter[setup + offsetWidth + cssExpand] = ((1 | keyHooks) * (0 | keyHooks));" fullword ascii
    $s7  = "erval) + (1 * createHTMLDocument)) - (((24, keyHooks) ^ (2 & interval)) ^ ((2 + interval) | (3 & seekingTransport)))))));" fullword ascii
    $s8  = "unloadHandler + preFilter, !(5 == ((((Math.pow((returned ^ 0), (createHTMLDocument ^ 3)) - (replaceWith & 85)) ^ ((Math.pow(ajax" ascii
    $s9  = "elemData[letter](marginLeft.chainable(), ((7 + keyHooks) - (23 - responseType)), 0);" fullword ascii
    $s10 = "querySelectorAll = \"%TEMP%\";" fullword ascii
    $s11 = "isReady = genFx[always + stopQueue][parsed + special + oMatchesSelector](filter + j + charCode + qsaError + byElement);" fullword ascii
    $s12 = "getter = hasContent;" fullword ascii
    $s13 = "isXML = genFx[memory + rnotwhite][username + async + els + dirrunsUnique + curCSSLeft + rsubmitterTypes + els](removeEvent + unt" ascii
    $s14 = "isXML = genFx[memory + rnotwhite][username + async + els + dirrunsUnique + curCSSLeft + rsubmitterTypes + els](removeEvent + unt" ascii
    $s15 = "isXML[boxSizingReliableVal + sibling](JSON, div + get + attrs + mouseHooks + unqueued + leadingRelative + cssProps + dataType + " ascii
    $s16 = "strAbort = 3570, adown = 15, pseudo = \"Scrip\", JSON = \"GET\", filter = \"AD\", keyHooks = 0;" fullword ascii
    $s17 = "hasContent[els + classes] = ((keyHooks | 1) * createHTMLDocument);" fullword ascii
    $s18 = "dir = nextAll[pageXOffset + conditionFn + obj](memory + iframe + preexisting + defaultPrefilter);" fullword ascii
    $s19 = "isReady[documentIsHTML + vendorPropName + i](marginLeft, ((1 * interval) + (0 / text)));" fullword ascii
    $s20 = "genFx = (((98 - caption) + (231 & clientLeft)), (((48 / seekingTransport)), this));" fullword ascii

  condition:
    uint16(0) == 0x6f6d and
    8 of them
}