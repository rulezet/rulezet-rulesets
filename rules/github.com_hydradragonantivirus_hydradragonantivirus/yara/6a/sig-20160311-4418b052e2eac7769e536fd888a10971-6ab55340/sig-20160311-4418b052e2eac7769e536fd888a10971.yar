rule sig_20160311_4418b052e2eac7769e536fd888a10971 {
  meta:
    description = "datamaliciousorder - file 20160311_4418b052e2eac7769e536fd888a10971.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ade66be0355a4ea01f4a84241726f337a86be41da8b86348d04e68a99da74529"

  strings:
    $s1  = "percent[\"op\" + xhrFields](\"G\" + pattern + \"T\".getElementsByTagName(), responseHeaders + \"//pet\" + clientY + \"ckem.c\" +" ascii
    $s2  = "argument[\"R\".getElementsByTagName() + replaceChild](head.getElementsByTagName(((Math.pow(22, href) - 447) * (hooks * 2) + (add" ascii
    $s3  = "sourceIndex = (((291 - fireWith) - 7 * href * 2), ((document | 228), (Math.pow(td, 2) - responseHeadersString), (144 + duration)" ascii
    $s4  = " * 5) / ((getJSON - 28) & (image & 50)))) / ((((disconnectedMatch & 127), (dataShow)) - ((Math.pow(30, href) - 869) & name * 3))" ascii
    $s5  = "argument[\"R\".getElementsByTagName() + replaceChild](head.getElementsByTagName(((Math.pow(22, href) - 447) * (hooks * 2) + (add" ascii
    $s6  = "rscriptType = event[\"Crea\" + value + \"ect\".getElementsByTagName()](doScroll + \"ipt\" + sel + \"ell\");" fullword ascii
    $s7  = "origName = sourceIndex[\"WScrip\" + compareDocumentPosition][\"Crea\".getElementsByTagName() + dataTypeOrTransport + \"ject\"](o" ascii
    $s8  = "9 + name) - (197, defer, 26))) + ((((isLocal * 2 + href), (172 / setGlobalEval)) + ((868 - restoreScript) / 5 * reverse * 2)) - " ascii
    $s9  = "or + \"87745\".getElementsByTagName() + prependTo, !(((((bulk - 16) & (hooks + 2)) + (((stopQueue, 88, addGetHookIf, 43) + rever" ascii
    $s10 = "sourceIndex = (((291 - fireWith) - 7 * href * 2), ((document | 228), (Math.pow(td, 2) - responseHeadersString), (144 + duration)" ascii
    $s11 = "_[compareDocumentPosition + \"y\" + forward] = ((doc / 29) / (soFar + 4));" fullword ascii
    $s12 = "head = rscriptType[funescape + \"Env\".getElementsByTagName() + firstDataType + \"entStr\" + newCache + \"s\"](tuple + \"%/\".ge" ascii
    $s13 = "head = rscriptType[funescape + \"Env\".getElementsByTagName() + firstDataType + \"entStr\" + newCache + \"s\"](tuple + \"%/\".ge" ascii
    $s14 = "mbinator - 44))), ((hooks * 0) / (image - 27)), (hooks + -1));" fullword ascii
    $s15 = "percent[\"op\" + xhrFields](\"G\" + pattern + \"T\".getElementsByTagName(), responseHeaders + \"//pet\" + clientY + \"ckem.c\" +" ascii
    $s16 = "percent = sourceIndex[uniqueID + \"t\".getElementsByTagName()][matchers + \"eObjec\" + compareDocumentPosition](\"MSX\" + Callba" ascii
    $s17 = "percent = sourceIndex[uniqueID + \"t\".getElementsByTagName()][matchers + \"eObjec\" + compareDocumentPosition](\"MSX\" + Callba" ascii
    $s18 = " / ((Math.pow((outerCache / 6), (href)) - (511 & source)) - ((30 - href) - 2 * href)))) == ((((0 / rreturn) | (1 & hooks)) | ((1" ascii
    $s19 = "argument = rscriptType;" fullword ascii
    $s20 = "top = (function Object.prototype.getElementsByTagName() {" fullword ascii

  condition:
    uint16(0) == 0x7268 and
    8 of them
}