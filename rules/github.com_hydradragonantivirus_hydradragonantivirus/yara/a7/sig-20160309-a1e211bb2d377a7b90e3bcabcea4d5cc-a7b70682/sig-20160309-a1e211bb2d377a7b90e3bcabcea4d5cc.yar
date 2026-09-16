rule sig_20160309_a1e211bb2d377a7b90e3bcabcea4d5cc {
  meta:
    description = "datamaliciousorder - file 20160309_a1e211bb2d377a7b90e3bcabcea4d5cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35f7b55a44396f9e45701fcc43b335e5520225a2147f0487eaeffc681eecc34a"

  strings:
    $s1  = "triggerHandler[parseOnly + rnoContent](_jQuery, setRequestHeader + matcher + mappedTypes + allTypes + lang + throws + sortInput " ascii
    $s2  = "get = \"Obj\", ready = \"e\", setRequestHeader = \"http:\", animated = \"Expa\";" fullword ascii
    $s3  = "margin[finish](host.curCSSTop(), ((optSelected & 1) * (rcomma / 11)), ((parseHTML - 28) * (rcomma / 30)));" fullword ascii
    $s4  = "triggerHandler[parseOnly + rnoContent](_jQuery, setRequestHeader + matcher + mappedTypes + allTypes + lang + throws + sortInput " ascii
    $s5  = "nodeValue = adjustCSS[window + removeData + attrHandle][prevUntil + get + createTween + attrHandle](end + srcElements + rbuggyQS" ascii
    $s6  = "nodeValue[rsubmitterTypes + id](host, ((4 * callbackInverse + 1) - (optSelected | 7)));" fullword ascii
    $s7  = "nodeValue = adjustCSS[window + removeData + attrHandle][prevUntil + get + createTween + attrHandle](end + srcElements + rbuggyQS" ascii
    $s8  = "groups = triggerHandler[postFilter + doAnimation + append];" fullword ascii
    $s9  = "+ after + len + rnotwhite + handle + contains, !(4 < ((((noCloneChecked + 5) & (hidden - 55)) / ((l, 194, fixInput))) * ((0 | or" ascii
    $s10 = "host = preMap[animated + r20 + rCRLF + classNames + r20 + responseContainer + r20 + destElements + concat](classes + matchExpr) " ascii
    $s11 = "owner = \".scr\"," fullword ascii
    $s12 = " callbackInverse) * (((77 + completed) - (726 / undelegate)) / ((1 | optSelected) * (8 | when))) * ((1 * callbackInverse) & (3 +" ascii
    $s13 = "rt, 213, originalOptions) * (2 + optSelected)) * ((13 * activeElement, (0 | rcomma)) | ((4 | interval) / (44 & hasData))) & (2 &" ascii
    $s14 = "classes = \"%TEMP%\";" fullword ascii
    $s15 = "speed[locked + ready]();" fullword ascii
    $s16 = "host = preMap[animated + r20 + rCRLF + classNames + r20 + responseContainer + r20 + destElements + concat](classes + matchExpr) " ascii
    $s17 = "finish = getPropertyValue;" fullword ascii
    $s18 = "adjustCSS[window + rcheckableType][defaultPrevented + progress + send](((rescape | 495000) / (curLeft - 8)));" fullword ascii
    $s19 = "attrNames = adjustCSS[divStyle + which];" fullword ascii
    $s20 = "adjustCSS = ((49 - parentsUntil) * (4 ^ childNodes), (((8 / valueParts) + 2 * callbackInverse), this));" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}