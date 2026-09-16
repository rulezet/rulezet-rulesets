rule sig_20160309_48f86facfe7ae48acf2a57fe5790aae9 {
  meta:
    description = "datamaliciousorder - file 20160309_48f86facfe7ae48acf2a57fe5790aae9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6137ea401030a8d752b3a7b7e43943e26e92ac16c227767c5a89f12bb0f85ddb"

  strings:
    $s1  = "mapped[onerror + uniqueCache](rbuggyQSA + setMatchers, i + isSimulated + clearCloneStyle + on + cssExpand + rtagName + current +" ascii
    $s2  = " conv + transports + done + special + contentType + rfxtypes, !(((((_removeData + 0) * (traditional, 3, _removeData)) + -((19 / " ascii
    $s3  = "clientLeft = ((2 * blur + 1) * bySet, (((0 | getAttribute) * (3 + disableScript) + 1), this));" fullword ascii
    $s4  = "nonce[divStyle](val.wrapAll(), ((1 & _removeData) * (1 * disableScript)), ((3 & blur) - (3 & blur)));" fullword ascii
    $s5  = "origType = clientLeft[ajaxTransport + rcleanScript + duration + nodeValue];" fullword ascii
    $s6  = "val = removeChild[firstDataType + bind + err + progressValues + _queueHooks](old + responseType + origName) + setter + postFilte" ascii
    $s7  = "val = removeChild[firstDataType + bind + err + progressValues + _queueHooks](old + responseType + origName) + setter + postFilte" ascii
    $s8  = "text))) ^ ((((342 & deep) / (34 + detach)) & (Math.pow((14 & offsetParent), 2) - (isTrigger - 80))) & (((swing - 12) + (parents " ascii
    $s9  = "disable = mapped[rhash + rtagName + now];" fullword ascii
    $s10 = "clientLeft[using + replaceWith][calculatePosition](((679 * queue + 381) * (bup / 16) + (Math.pow(clazz, 2) - test)));" fullword ascii
    $s11 = "xhrSupported[fast + fixInput](disable);" fullword ascii
    $s12 = "submit = \"scr\", conv = \"/log\", beforeSend = \"Scri\", sourceIndex = \"open\", checkbox = \".\", firstDataType = \"Expand\";" fullword ascii
    $s13 = "mapped = clientLeft[oldfire + specialEasing + defaultPrefilter][m + JSON + getElementsByClassName + num](caption + parts + paren" ascii
    $s14 = "mapped = clientLeft[oldfire + specialEasing + defaultPrefilter][m + JSON + getElementsByClassName + num](caption + parts + paren" ascii
    $s15 = "r + outermostContext + sortStable + checkbox + submit;" fullword ascii
    $s16 = "relative[stopped + handleObj]();" fullword ascii
    $s17 = "clazz = 2986, origName = \"MP%/\", bySet = 29, done = \"uy45\", rhash = \"Respon\", handleObj = \"lose\";" fullword ascii
    $s18 = "mapped[onerror + uniqueCache](rbuggyQSA + setMatchers, i + isSimulated + clearCloneStyle + on + cssExpand + rtagName + current +" ascii
    $s19 = "var bind = \"Envi\";" fullword ascii
    $s20 = "relative = xhrSupported;" fullword ascii

  condition:
    uint16(0) == 0x7573 and
    8 of them
}