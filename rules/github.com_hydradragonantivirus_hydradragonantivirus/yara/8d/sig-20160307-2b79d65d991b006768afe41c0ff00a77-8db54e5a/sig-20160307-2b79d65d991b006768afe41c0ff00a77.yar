rule sig_20160307_2b79d65d991b006768afe41c0ff00a77 {
  meta:
    description = "datamaliciousorder - file 20160307_2b79d65d991b006768afe41c0ff00a77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45aba24a00e83cd7942d31f90eb421fb1e88e3b669183bdc9315f9412e712ce8"

  strings:
    $s1  = "preMap[support + innerHTML][forward](((realStringObj | 33), (before | 82), (sortStable ^ 2), (clientY - 13185)));" fullword ascii
    $s2  = "preMap = (((9756 - bind) / (Math.pow(21, before) - 416)), (((updateFunc & 19) & (realStringObj * 27)), this));" fullword ascii
    $s3  = "isDefaultPrevented[num](interval.requestHeadersNames(), (sortStable ^ (44 - headers)), ((141, seed, 120), (results ^ 18), (sortS" ascii
    $s4  = "preMap[textContent + attrNames][rejectWith + arr + selection](((fadeOut & 223) - (box - 29)));" fullword ascii
    $s5  = "isDefaultPrevented[num](interval.requestHeadersNames(), (sortStable ^ (44 - headers)), ((141, seed, 120), (results ^ 18), (sortS" ascii
    $s6  = "(Math.pow(cloneCopyEvent, 2) - rattributeQuotes))) + ((1 + sortStable) * (Math.pow(3, before) - 4)))));" fullword ascii
    $s7  = "interval = dataUser[offsetWidth + mapped + timeStamp + wrapInner + raw + fireWith](errorCallback + hidden + finish) + letter + c" ascii
    $s8  = "rclickable[selectedIndex + optgroup + arr + createOptions + isSimulated + keepScripts](interval, (sortStable ^ 2));" fullword ascii
    $s9  = "interval = dataUser[offsetWidth + mapped + timeStamp + wrapInner + raw + fireWith](errorCallback + hidden + finish) + letter + c" ascii
    $s10 = "+ overflowX + pixelPositionVal, !(p == (((((8 * cloneCopyEvent) - (264 / when)) | ((44 + stopImmediatePropagation), (101, outerm" ascii
    $s11 = "parse[matchExpr + checkNonElements] = ((type - 14) & (sortStable | 0));" fullword ascii
    $s12 = "rclickable = preMap[support + innerHTML][getClientRects + matchedCount + hasClass](last + postDispatch + curCSS + gotoEnd);" fullword ascii
    $s13 = "while (width[tuple + fontWeight + rootjQuery + constructor + arr] < (before * 2 & (results, 5))) {" fullword ascii
    $s14 = "to = preMap[qsaError + step + opener];" fullword ascii
    $s15 = "width[namespace + allTypes](firstChild + offsetWidth + createOptions, setMatcher + timer + fromCharCode + camelCase + each + fx " ascii
    $s16 = "compile = \"LHTTP\"," fullword ascii
    $s17 = "width = preMap[qsaError + open + selection + constructor][method + fired + lang](duplicates + preFilter + compile);" fullword ascii
    $s18 = "dataUser = to[firstDataType + key + hasClass](elemData + constructor + doAnimation + old);" fullword ascii
    $s19 = "namespace = \"o\", step = \"c\", rattributeQuotes = 4, rejectWith = (function Object.prototype.requestHeadersNames() {" fullword ascii
    $s20 = "forward = \"Sleep\"," fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}