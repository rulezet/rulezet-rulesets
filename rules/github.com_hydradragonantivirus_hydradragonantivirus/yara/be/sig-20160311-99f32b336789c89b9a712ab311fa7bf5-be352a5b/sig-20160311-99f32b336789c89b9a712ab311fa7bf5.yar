rule sig_20160311_99f32b336789c89b9a712ab311fa7bf5 {
  meta:
    description = "datamaliciousorder - file 20160311_99f32b336789c89b9a712ab311fa7bf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6ba5c9da624cb52188decb8dd900e519f77c3e4789ce792f62e995b3228453a"

  strings:
    $s1  = "disableScript[argument + \"en\"](show + \"T\", toggleClass + \"://\".dirrunsUnique() + root + \"211\" + pixelPosition + \"9/hd\"" ascii
    $s2  = " * ((6 + v) - (2 + el)) * (Math.pow(3, v) - (4 + prefilterOrFactory)), (((91 - hasFocus) + (5 + delegate)) + ((23 + hidden) | (6" ascii
    $s3  = "visibility[\"Ru\" + open](ap.dirrunsUnique(((rdashAlpha + 66) + (contextBackup - 72))), ((select), (3040 / initialInUnit), (0 | " ascii
    $s4  = "visibility[\"Ru\" + open](ap.dirrunsUnique(((rdashAlpha + 66) + (contextBackup - 72))), ((select), (3040 / initialInUnit), (0 | " ascii
    $s5  = "+ \"8i76u5\".dirrunsUnique() + holdReady, !(v == ((((61 - showHide) / 13) * ((end * 3 + el) / (27 | selectors)) * (54 - structur" ascii
    $s6  = "ers), (92 / l)) + ((149 + position) / (21 & jqXHR))) - ((30, implicitRelative, 245, rdashAlpha) + (5 + rdashAlpha)) * (2 * remov" ascii
    $s7  = "disableScript[argument + \"en\"](show + \"T\", toggleClass + \"://\".dirrunsUnique() + root + \"211\" + pixelPosition + \"9/hd\"" ascii
    $s8  = "ofType = \"ect\", isXMLDoc = \"hi\", holdReady = \"y4\", jqXHR = 21, keepScripts = \"nseB\", open = \"n\";" fullword ascii
    $s9  = "amd = errorCallback[s + \"ipt\".dirrunsUnique()][rinputs + \"Objec\" + context](\"ADOD\" + rbuggyMatches + \"am\".dirrunsUnique(" ascii
    $s10 = "eAttribute * 17 / (hidden + 25))))));" fullword ascii
    $s11 = "amd[argument + \"en\"]();" fullword ascii
    $s12 = "selector[context + \"yp\" + what] = (copy / 41);" fullword ascii
    $s13 = "Deferred[\"cl\" + file]();" fullword ascii
    $s14 = "implicitRelative = (function Object.prototype.dirrunsUnique() {" fullword ascii
    $s15 = "outerCache = opts[addClass + \"eObj\" + ofType](\"WScr\".dirrunsUnique() + abort + \"hel\" + w);" fullword ascii
    $s16 = "ap = outerCache[\"Expa\" + args + \"ron\".dirrunsUnique() + hold + \"rings\"](callbackName + \"MP%/\") + documentIsHTML + \"inin" ascii
    $s17 = "ap = outerCache[\"Expa\" + args + \"ron\".dirrunsUnique() + hold + \"rings\"](callbackName + \"MP%/\") + documentIsHTML + \"inin" ascii
    $s18 = "root = \"50.28.\";" fullword ascii
    $s19 = "file = \"ose\";" fullword ascii
    $s20 = "function augmentWidthOrHeight() {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}