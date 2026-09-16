rule sig_20160309_e3fe363dac23c7b824a3a16c08090777 {
  meta:
    description = "datamaliciousorder - file 20160309_e3fe363dac23c7b824a3a16c08090777.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95930c8d0decac87efc156cced9e10c33e514be6ab62a845db742e06487eaba2"

  strings:
    $s1  = "oldfire[offset](overwritten + beforeSend, isFunction + origFn + firstChild + preMap + cssHooks + file + duplicates + qsaError + " ascii
    $s2  = "originalSettings = (((Math.pow(294, defer) - 86107) & (runescape * 20 + jqXHR)), (((33 - getResponseHeader) & (0 ^ all)), this))" ascii
    $s3  = "originalSettings = (((Math.pow(294, defer) - 86107) & (runescape * 20 + jqXHR)), (((33 - getResponseHeader) & (0 ^ all)), this))" ascii
    $s4  = "fadeOut[isXML + isSuccess + trigger + unbind](opener, ((95, reliableMarginRight, 17) - xhrSupported * 3));" fullword ascii
    $s5  = "ported) ^ (210 / stopped)))) - (((336 / bind) & (39 - marginRight)) * ((1 + -resolveValues) ^ (0 ^ index)) + ((40 - stopped) - (" ascii
    $s6  = "opener = rsibling[responseHeaders + parts + matched + resolveContexts + readyWait + mapped](wrapAll + finalValue + append) + els" ascii
    $s7  = "opener = rsibling[responseHeaders + parts + matched + resolveContexts + readyWait + mapped](wrapAll + finalValue + append) + els" ascii
    $s8  = "oldfire = originalSettings[ajaxTransport + oldCallbacks][host + rclickable + calculatePosition + oldCallbacks](ajax + compareDoc" ascii
    $s9  = "1 + -resolveValues)))) == (3 + (((rcombinators | 2) * (defer | 0)) | ((index + 0) | (Deferred ^ 7))))));" fullword ascii
    $s10 = "oldfire = originalSettings[ajaxTransport + oldCallbacks][host + rclickable + calculatePosition + oldCallbacks](ajax + compareDoc" ascii
    $s11 = " (3 | (valueIsBorderBox ^ 60)), ((unloadHandler & 6) & (index | 2))), ((Math.pow(index, 2) - all) * (23 - jqXHR) - ((12 + xhrSup" ascii
    $s12 = "which[reliableMarginLeftVal](opener.check(), ((1 & rcombinators) / (5 | Deferred)), ((1 * rcombinators) | (45 - rwhitespace)));" fullword ascii
    $s13 = "chainable + always, !((Math.pow((((75 ^ guaranteedUnique) - (2198 / nodeNameSelector)), ((80 | rcssNum) / (10 | resolveValues))," ascii
    $s14 = "originalSettings[relative + MAX_NEGATIVE + cached][_removeData + teardown + pageXOffset]((Math.pow((escaped / 43), (defer + 0)) " ascii
    $s15 = "mapped = \"gs\", host = \"Cre\", undelegate = \"send\", getAll = 13, teardown = \"l\";" fullword ascii
    $s16 = "postSelector = originalSettings[relative + rnoInnerhtml + context];" fullword ascii
    $s17 = "postFilter = oldfire[display + noBubble + clearCloneStyle];" fullword ascii
    $s18 = "qualifier = \".scr\";" fullword ascii
    $s19 = "current[position + unbind]();" fullword ascii
    $s20 = "responseHeaders = \"E\", relative = \"WSc\";" fullword ascii

  condition:
    uint16(0) == 0x6e69 and
    8 of them
}