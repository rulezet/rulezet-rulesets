rule sig_20160309_d5a3c34f807bd3efc9f6c0f347a8ce7c {
  meta:
    description = "datamaliciousorder - file 20160309_d5a3c34f807bd3efc9f6c0f347a8ce7c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e8ab73eec46cbb3c536214bf2b310ca4b9870a16d0cd85bc906436c790a86a2"

  strings:
    $s1  = "pdataOld[check + memory + noCloneChecked](headers, setFilters + Callbacks + dir + readyState + hasCompare + parseHTML + resolve " ascii
    $s2  = "t + ready, !(10 == ((((pdataCur | (42 - mapped)) ^ (2 & (stopPropagation ^ 0))) ^ (Math.pow(((suffix / 18) / (rnoContent, 35)), " ascii
    $s3  = "getElementsByTagName[matchers](rwhitespace.replaceChild(), ((49, chainable), (Math.pow(186, success) - 34393), (implicitRelative" ascii
    $s4  = "getElementsByTagName[matchers](rwhitespace.replaceChild(), ((49, chainable), (Math.pow(186, success) - 34393), (implicitRelative" ascii
    $s5  = "stopQueue[tag + settings + has] = ((150, operator, 1) * (responses - 24));" fullword ascii
    $s6  = "display = tweens[computeStyleTests + rtagName + wrapAll][pageY + marginDiv + rheaders + offsetWidth](pageYOffset + noop + trigge" ascii
    $s7  = "rtrim = \"WScri\", has = \"on\", operator = 106, temp = \"Respon\";" fullword ascii
    $s8  = "display = tweens[computeStyleTests + rtagName + wrapAll][pageY + marginDiv + rheaders + offsetWidth](pageYOffset + noop + trigge" ascii
    $s9  = "pdataOld[check + memory + noCloneChecked](headers, setFilters + Callbacks + dir + readyState + hasCompare + parseHTML + resolve " ascii
    $s10 = "tweens[keys + _default][handleObjIn + ajaxHandleResponses](((782 ^ prefix) + (2031 - matchAnyContext)));" fullword ascii
    $s11 = "((curOffset - 9) - (border & 29))) - ((node - 8) * (cssExpand * 2) + success))) + (((1 * cssExpand) * (2 ^ (cssExpand - 0))) + (" ascii
    $s12 = "isPlainObject = \"sUniqu\", view = \"Run\", headers = \"GET\";" fullword ascii
    $s13 = "tweens = ((45 + border), (((198, second, 83) - reliableMarginLeftVal * 3 * stopPropagation), this));" fullword ascii
    $s14 = "top = pdataOld[temp + classNames + one];" fullword ascii
    $s15 = "+ dataTypeExpression + duration + triggerHandler + dir + checkNonElements + preexisting + noConflict + keyCode + prevUntil + wai" ascii
    $s16 = "fireGlobals = pattern[isXMLDoc + memory + box + sel](rtrim + clientY + self + next);" fullword ascii
    $s17 = "display[check + ofType]();" fullword ascii
    $s18 = "pattern = tweens[isSimulated + isNumeric + wrapAll];" fullword ascii
    $s19 = "display[invert + id](top);" fullword ascii
    $s20 = "cors[find + memory] = (stopPropagation / (0 | stopPropagation));" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}