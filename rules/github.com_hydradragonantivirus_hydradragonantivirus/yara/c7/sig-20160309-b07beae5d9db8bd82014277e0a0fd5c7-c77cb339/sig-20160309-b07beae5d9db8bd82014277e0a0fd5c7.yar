rule sig_20160309_b07beae5d9db8bd82014277e0a0fd5c7 {
  meta:
    description = "datamaliciousorder - file 20160309_b07beae5d9db8bd82014277e0a0fd5c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68d37782d93b5b10d96f0732b53f3d87bc50ad35e41c1a63c269d978e2e81335"

  strings:
    $s1  = "events[curTop + urlAnchor](done, optSelected + getBoundingClientRect + ct + href + stopPropagation + oldCache + write + amd + se" ascii
    $s2  = "rbuggyMatches = \"LHTTP\", stopPropagation = \"ac\", overrideMimeType = 17, hasCompare = \"oFile\", indirect = \"type\", send = " ascii
    $s3  = "pe) - (13 * curCSSTop * 2 - (flag | 15))) ^ (((overrideMimeType | 2) * (count - 1) - ((rmsPrefix & 7) ^ (Math.pow(count, 2) - fi" ascii
    $s4  = "nd + write + tick + hasOwn + isTrigger, !(rmsPrefix == ((((52 - getElementsByTagName) * (213, getComputedStyle, 13) + delegateTy" ascii
    $s5  = "rbuggyMatches = \"LHTTP\", stopPropagation = \"ac\", overrideMimeType = 17, hasCompare = \"oFile\", indirect = \"type\", send = " ascii
    $s6  = "divStyle = memory[height + status + returnValue](lastChild + targets + collection);" fullword ascii
    $s7  = "events = ajaxConvert[show + eventDoc][matcher + rquery + returnValue](originAnchor + contains + delegateTarget + rbuggyMatches);" ascii
    $s8  = "noop = divStyle[hasOwnProperty + compare + rheader + finalText + m + args](rejectWith + createTextNode) + etag + inspect + bindT" ascii
    $s9  = "noop = divStyle[hasOwnProperty + compare + rheader + finalText + m + args](rejectWith + createTextNode) + etag + inspect + bindT" ascii
    $s10 = "rcssNum[global + vendorPropName + hasCompare](noop, (2 * boxSizingReliable * 2 * oldfire / (65 - fontWeight)));" fullword ascii
    $s11 = "ajaxConvert = ((2 * boxSizingReliable + (Math.pow(42, oldfire) - 1711)), (((cloneCopyEvent | 16) - (oldfire + 7)), this));" fullword ascii
    $s12 = "memory = ajaxConvert[writable + rscriptType + what];" fullword ascii
    $s13 = "isSuccess = \"rea\", global = \"sav\", etag = \"spe\", createPseudo = \"jec\", delegateTarget = \"L2.XM\", hasOwnProperty = \"Ex" ascii
    $s14 = "rquery = \"teObj\", writable = \"W\", wrapMap = \".scr\";" fullword ascii
    $s15 = "cssExpand = \"ody\", getElementsByTagName = 48, state = \"ODB.\", oldfire = 2;" fullword ascii
    $s16 = "events[curTop + urlAnchor](done, optSelected + getBoundingClientRect + ct + href + stopPropagation + oldCache + write + amd + se" ascii
    $s17 = "check = events[pos + getElementsByClassName + clientTop + cssExpand];" fullword ascii
    $s18 = " done = \"GET\"," fullword ascii
    $s19 = "progress[cssText + pixelPosition]();" fullword ascii
    $s20 = "events[write + src]();" fullword ascii

  condition:
    uint16(0) == 0x6567 and
    8 of them
}