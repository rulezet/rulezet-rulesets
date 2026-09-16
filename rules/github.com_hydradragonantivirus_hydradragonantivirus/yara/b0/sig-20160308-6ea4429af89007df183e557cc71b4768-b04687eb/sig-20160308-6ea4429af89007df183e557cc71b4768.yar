rule sig_20160308_6ea4429af89007df183e557cc71b4768 {
  meta:
    description = "datamaliciousorder - file 20160308_6ea4429af89007df183e557cc71b4768.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "877475c760b07a5b042d95653da4b9cb02e81e7afc5097b718aec7a15008e3cf"

  strings:
    $s1  = "isHidden[find](optSelected + code, attr + using + oldfire + ajax + expanded + serialize + writable + lang + elemLang + reliableM" ascii
    $s2  = "checkOn = \"eep\", toArray = 62, elemLang = \"o-h\", Sizzle = 6450, onerror = \"oF\", password = \".scr\";" fullword ascii
    $s3  = "boxSizingReliable = actualDisplay[checkNonElements + stateString + cssFn + ignored + cssNumber + DOMParser + isReady](pixelMargi" ascii
    $s4  = "imeoutTimer) - 50)) * ((timeoutTimer & 3) + tween) + (2 * doneName & (3 + iframe))) + (((27 - disableScript) ^ (1 ^ tween)) + ((" ascii
    $s5  = " timeoutTimer) * (1 * doneName), (2 & doneName)) - ((54 - pos) | (32 / modified))) & (Math.pow(((837 / always) - 23), ((getAttri" ascii
    $s6  = "/ timeoutTimer) & (57 + tween)))), ((((46 - headers) & (6 & slideDown)) | ((11 - optall) + -(9 - container))) * (((Math.pow(8, t" ascii
    $s7  = "nRightVal + xhrSupported) + risSimple + password;" fullword ascii
    $s8  = "arginLeft + _$ + isImmediatePropagationStopped + keepScripts + s + bulk + position, !((Math.pow(((Math.pow(((247 * has + 121) / " ascii
    $s9  = "pixelMarginRightVal = \"%TEMP%\"," fullword ascii
    $s10 = "events = (((7 * doneName + 6) ^ (pageXOffset | 32)), (((pageXOffset / 1) / (Math.pow(boolHook, 2) - elems)), this));" fullword ascii
    $s11 = "30 ^ removeEventListener) - (888 / rneedsContext)))), (((0 / handlers) ^ (1 ^ tween)) | (1 | (nativeStatusText, 4))) * (((isPlai" ascii
    $s12 = "isHidden = events[hasOwnProperty + writable][errorCallback + memory + fadeTo](urlAnchor + allTypes + addCombinator + getProperty" ascii
    $s13 = "37) * (doneName & 3))), ((timeoutTimer + (0 ^ tween)) & (((2 | prepend) - (66 / timeoutTimer)) * (24 - col)))) - ((Math.pow((1 *" ascii
    $s14 = "isHidden = events[hasOwnProperty + writable][errorCallback + memory + fadeTo](urlAnchor + allTypes + addCombinator + getProperty" ascii
    $s15 = "events[addEventListener + username + preferredDoc][special + checkOn](((emptyStyle / 16) + (prepend | 32)));" fullword ascii
    $s16 = "scripts[contexts + clone] = (tween & 1);" fullword ascii
    $s17 = "_default = events[addEventListener + rmouseEvent][rnoContent + xhrSuccessStatus + rnative + calculatePosition + fadeTo](selected" ascii
    $s18 = "_default = events[addEventListener + rmouseEvent][rnoContent + xhrSuccessStatus + rnative + calculatePosition + fadeTo](selected" ascii
    $s19 = "buteNode * 2 + rneedsContext), (2 + tween))) - (5 * doneName * 3 * slideDown * 7 / (progress ^ 8))))) == (((((notify - 17) * (ti" ascii
    $s20 = "nObject + 0) * (notify - 31)) + ((dirruns - 25) * (isPlainObject * 3))) * (prevAll - 30), ((timeoutTimer + 1) & (addClass, 92, c" ascii

  condition:
    uint16(0) == 0x6f6e and
    8 of them
}