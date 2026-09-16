rule sig_20160311_c4c1607dea784c799ac48fd461e51694 {
  meta:
    description = "datamaliciousorder - file 20160311_c4c1607dea784c799ac48fd461e51694.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "37ef693f52815dba685c156cfb11772bd87f8d6193bcd4dc989eba42f7252bfd"

  strings:
    $s1  = "cloneNode[conditionFn + \"en\"](createPositionalPseudo + \"T\", tweens + \"://pet\".namespace() + getAllResponseHeaders + \"ckem" ascii
    $s2  = "))) / ((((Math.pow(28, createTween) - 739) & (adown, 45)) * ((manipulationTarget - 16) * (createTween & 3)) + ((Math.pow(webkitM" ascii
    $s3  = "tokenize = rcleanScript[sortStable + \"ndEnv\" + first + \"entSt\".namespace() + round](\"%TEMP\" + nodeName) + \"pro\" + protot" ascii
    $s4  = "tokenize = rcleanScript[sortStable + \"ndEnv\" + first + \"entSt\".namespace() + round](\"%TEMP\" + nodeName) + \"pro\" + protot" ascii
    $s5  = "setTimeout = ((Math.pow(20, createTween) - 371), ((Math.pow(isFunction, 2) - size) - (1025 / maxIterations)), eval(\"t\" + propF" ascii
    $s6  = ", ((fn & 71), (fromCharCode - 111), (copy - 109)), ((send + 101)), ((on * 2 + createTween) | (Math.pow(71, createTween) - 4969))" ascii
    $s7  = "setTimeout = ((Math.pow(20, createTween) - 371), ((Math.pow(isFunction, 2) - size) - (1025 / maxIterations)), eval(\"t\" + propF" ascii
    $s8  = "cloneNode = setTimeout[\"WScri\" + isLocal][\"Creat\".namespace() + callbackName + \"jec\" + outermost](\"MSXML2\" + username + " ascii
    $s9  = "cloneNode = setTimeout[\"WScri\" + isLocal][\"Creat\".namespace() + callbackName + \"jec\" + outermost](\"MSXML2\" + username + " ascii
    $s10 = "cloneNode[requestHeadersNames + \"n\".namespace() + fast]();" fullword ascii
    $s11 = "className = setTimeout[\"WScr\" + getBoundingClientRect][\"Create\" + focus + \"ect\".namespace()](append + \".Str\" + col);" fullword ascii
    $s12 = "getAllResponseHeaders = \"erdi\", then = 1960, each = \"write\", tmp = 237, adown = 158;" fullword ascii
    $s13 = "top[copyIsArray + \"n\".namespace()](tokenize.namespace(((cssExpand + 1477) / (then / 40))), ((nType & 1) * (isArray)), ((1 * is" ascii
    $s14 = "top[copyIsArray + \"n\".namespace()](tokenize.namespace(((cssExpand + 1477) / (then / 40))), ((nType & 1) * (isArray)), ((1 * is" ascii
    $s15 = "function setRequestHeader() {" fullword ascii
    $s16 = "username = \".XM\", sortDetached = (function String.prototype.namespace() {" fullword ascii
    $s17 = "function rcombinators() {" fullword ascii
    $s18 = "return rchecked" fullword ascii
    $s19 = "soFar = 18;" fullword ascii
    $s20 = "round = \"rings\";" fullword ascii

  condition:
    uint16(0) == 0x666f and
    8 of them
}