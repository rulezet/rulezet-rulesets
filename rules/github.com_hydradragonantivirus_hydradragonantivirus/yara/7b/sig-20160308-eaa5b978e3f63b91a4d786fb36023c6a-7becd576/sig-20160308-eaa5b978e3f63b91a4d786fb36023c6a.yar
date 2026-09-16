rule sig_20160308_eaa5b978e3f63b91a4d786fb36023c6a {
  meta:
    description = "datamaliciousorder - file 20160308_eaa5b978e3f63b91a4d786fb36023c6a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "928aafba9c7583d2857c5748a3ca6d2662a293f9e7ec8bbc3270d388352002a7"

  strings:
    $s1  = "while (camelKey[relative + camelCase + combinator] < ((setTimeout, 175, getStyles, 135), delegateTarget * 7 * bubbleType, (17, s" ascii
    $s2  = "while (camelKey[relative + camelCase + combinator] < ((setTimeout, 175, getStyles, 135), delegateTarget * 7 * bubbleType, (17, s" ascii
    $s3  = "matchesSelector = requestHeaders[async + rfocusMorph + script + getResponseHeader + disconnectedMatch + serialize](_ + stored + " ascii
    $s4  = "matchesSelector = requestHeaders[async + rfocusMorph + script + getResponseHeader + disconnectedMatch + serialize](_ + stored + " ascii
    $s5  = "camelKey[getAttributeNode](isHidden, dispatch + isXMLDoc + overwritten + b + doneName + handle + responseContainer + letterSpaci" ascii
    $s6  = "defaultPrevented[content + combinator](camelKey[_removeData + pushStack + defaultExtra + needsContext]);" fullword ascii
    $s7  = " 0) ^ ((sortInput & 1) & (finalDataType | 1)))) * ((((addToPrefiltersOrTransports ^ 82) - (iterator / 45)), ((module ^ 3) + (ele" ascii
    $s8  = "requestHeaders = rclickable[serializeArray + getElementsByClassName + script];" fullword ascii
    $s9  = "rclickable[createTween + script][checkOn + parseXML](((3494 * structure + 2146) & (timers, 15005)));" fullword ascii
    $s10 = "camelKey = rclickable[createTween + script][removeClass + attributes + matcherIn + disconnectedMatch + serialize](winnow + uid +" ascii
    $s11 = "camelKey = rclickable[createTween + script][removeClass + attributes + matcherIn + disconnectedMatch + serialize](winnow + uid +" ascii
    $s12 = "empty[pixelPosition + obj] = ((finalDataType - 0) & (Sizzle, 1));" fullword ascii
    $s13 = "camelKey[getAttributeNode](isHidden, dispatch + isXMLDoc + overwritten + b + doneName + handle + responseContainer + letterSpaci" ascii
    $s14 = "rclickable[merge + always][filters + adjustCSS](((7894 - hooks) / (17 + overflow)));" fullword ascii
    $s15 = "script = \"t\";" fullword ascii
    $s16 = "var animated = \"trat\"," fullword ascii
    $s17 = "finalDataType = 0, serialize = \"ect\", parseXML = \"leep\", content = \"writ\", handle = \".\", makeArray = \"g\";" fullword ascii
    $s18 = "defaultPrevented[progress + opacity]();" fullword ascii
    $s19 = "rclickable = (((27 + before) & (16 * setAttribute + 15)), (((sortInput | 80) / (bubbleType + 4)), this));" fullword ascii
    $s20 = " opener + last + state);" fullword ascii

  condition:
    uint16(0) == 0x6964 and
    8 of them
}