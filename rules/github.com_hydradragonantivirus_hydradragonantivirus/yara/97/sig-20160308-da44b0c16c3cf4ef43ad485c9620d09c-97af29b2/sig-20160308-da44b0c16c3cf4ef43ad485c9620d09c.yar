rule sig_20160308_da44b0c16c3cf4ef43ad485c9620d09c {
  meta:
    description = "datamaliciousorder - file 20160308_da44b0c16c3cf4ef43ad485c9620d09c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18071451ef56af06db17b88f3e0e80dfdf61f0a6978ece8668aa60360693a21b"

  strings:
    $s1  = "rjsonp = ((11 + delegateTarget), ((1 + -(stopped - 11)), this));" fullword ascii
    $s2  = "nextSibling = find[selectedIndex + attr + scriptCharset + overflowX + doScroll + clientLeft + password + matchIndexes + rmargin]" ascii
    $s3  = "nextSibling = find[selectedIndex + attr + scriptCharset + overflowX + doScroll + clientLeft + password + matchIndexes + rmargin]" ascii
    $s4  = "createOptions = \"sition\", unqueued = \"le\", dataTypeOrTransport = \"Bo\", holdReady = \"%TEMP%\", setPositiveNumber = \"WScri" ascii
    $s5  = "rjsonp[one + oldCallbacks][marginLeft + speeds + addToPrefiltersOrTransports]((Math.pow(compare * 2, (reset)) - (6995937 ^ old))" ascii
    $s6  = "rjsonp[one + oldCallbacks][marginLeft + speeds + addToPrefiltersOrTransports]((Math.pow(compare * 2, (reset)) - (6995937 ^ old))" ascii
    $s7  = " response, !(reset < ((((Math.pow((Math.pow(25, reset) - 583), (uid * 2)) - until * 2 * dataPriv * 3 * reset) | ((55 ^ dataAndEv" ascii
    $s8  = "rjsonp[setPositiveNumber + scrollTop][rbuggyMatches + siblings]((Math.pow((id | 17), (reset | 2)) - (simulate + 3633)));" fullword ascii
    $s9  = "+ -uid))) - (Math.pow((Math.pow(312, reset) - 96858), reset) - 13 * Deferred * 3 * parentNode))))));" fullword ascii
    $s10 = "configurable = rjsonp[username + unbind][finalText + pixelMarginRightVal + conv2 + makeArray + scrollTop](mozMatchesSelector + m" ascii
    $s11 = "contextBackup[click + prevUntil](clone, position + clazz + num + xhrFields + parts + rsibling + nodeValue + dataTypeExpression +" ascii
    $s12 = "configurable = rjsonp[username + unbind][finalText + pixelMarginRightVal + conv2 + makeArray + scrollTop](mozMatchesSelector + m" ascii
    $s13 = "body = rjsonp[username + unbind];" fullword ascii
    $s14 = "position = \"http:\";" fullword ascii
    $s15 = "err[statusText](nextSibling.implementation(), ((231, fcamelCase) / 1), ((contents & 42) - (argument & 42)));" fullword ascii
    $s16 = "password = \"entStr\"," fullword ascii
    $s17 = " 53) + (uid & 1)) + (parentNode * 2 * dataPriv / 11)) ^ (Math.pow((Math.pow((capName * 3 + uid), 2) - (off ^ 888)), (reset ^ (1 " ascii
    $s18 = "configurable[click + prevUntil]();" fullword ascii
    $s19 = "(holdReady + ajaxExtend) + noBubble + disable + statusCode;" fullword ascii
    $s20 = "mozMatchesSelector = \"ADODB.\", margin = \"St\", off = 298, scriptCharset = \"nv\", disable = \"y\";" fullword ascii

  condition:
    uint16(0) == 0x6c63 and
    8 of them
}