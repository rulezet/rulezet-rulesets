rule sig_20160329_cffbf528ff4f07d061e0a4d3cf1f7ba3 {
  meta:
    description = "datamaliciousorder - file 20160329_cffbf528ff4f07d061e0a4d3cf1f7ba3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e34450703eb52af19fc2cfb2cf3213d5675b9e8fcdd340e7024fc120ff06f22"

  strings:
    $s1  = "file[\"ty\" + pointerleave] = ((tuple - 22), (etag + 9), (Math.pow(status, 2) - holdReady), 1);" fullword ascii
    $s2  = "file[els + \"ToFil\" + orig](rattributeQuotes, ((getPropertyValue | 18) / (send - 17)));" fullword ascii
    $s3  = "fix = timeStamp[\"WScri\" + fadeTo][\"Creat\" + pixelMarginRightVal + \"ct\"](preferredDoc[complete]);" fullword ascii
    $s4  = "function cssExpand(rscriptTypeMasked) {" fullword ascii
    $s5  = "file[attr + \"od\" + orig] = ((92 | children) / 31);" fullword ascii
    $s6  = "file[\"Writ\" + orig](fix[\"respo\" + handleObj + \"y\"]);" fullword ascii
    $s7  = "removeData = webkitMatchesSelector = filter = timeStamp = diff.xhrSupported();" fullword ascii
    $s8  = "function optionSet(tweeners, readyState) {" fullword ascii
    $s9  = "rsubmitterTypes(\"while%20%28fix%5B%22rea%22%20+%20blur%20+%20%22e%22%5D%20%21%3D%20%28%28preDispatch/19%29*%28Math.pow%28pdataO" ascii
    $s10 = "rsubmitterTypes(\"file%20%3D%20timeStamp%5Btoken%20+%20%22pt%22%5D%5Bseed%20+%20%22eObjec%22%20+%20focus%5D%28%22ADODB.%22%20+%2" ascii
    $s11 = "for (complete = ((_jQuery + 0) * reverse); complete < preferredDoc[callbackInverse]; complete++) {" fullword ascii
    $s12 = "rsubmitterTypes(\"while%20%28fix%5B%22rea%22%20+%20blur%20+%20%22e%22%5D%20%21%3D%20%28%28preDispatch/19%29*%28Math.pow%28pdataO" ascii
    $s13 = "rsubmitterTypes(\"filter%5B%22WSc%22%20+%20deep%5D%5B%22Sleep%22%5D%28%28%28pixelMarginRight%29*%282%26pixelMarginRight%29*%285%" ascii
    $s14 = "rsubmitterTypes(\"file%20%3D%20timeStamp%5Btoken%20+%20%22pt%22%5D%5Bseed%20+%20%22eObjec%22%20+%20focus%5D%28%22ADODB.%22%20+%2" ascii
    $s15 = "function cssNumber() {" fullword ascii
    $s16 = "function selected() {" fullword ascii
    $s17 = "initial();" fullword ascii
    $s18 = "function clientY() {" fullword ascii
    $s19 = "function triggerHandler() {" fullword ascii
    $s20 = "cssNumber(elemdisplay, origCount, pixelMarginRight, result);" fullword ascii

  condition:
    uint16(0) == 0x7263 and
    8 of them
}