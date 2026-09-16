rule sig_20160311_ef215362a0c569504e42c5199770bb43 {
  meta:
    description = "datamaliciousorder - file 20160311_ef215362a0c569504e42c5199770bb43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32b602ff4e2fc3d5e893ba551d2c546140b0fd98f260b30e03e63b0d778fc8ee"

  strings:
    $x1  = "bubbleType[rbracket + \"p\" + targets + \"n\"](camelCase + \"T\".innerText(), hookFn + \"p://w\" + tokenCache + \"stav.c\" + cla" ascii
    $x2  = "self[\"sav\" + rlocalProtocol + \"Fil\" + targets](combinator, ((Math.pow(48, content) - 2254) / setter * 5));" fullword ascii
    $s3  = " + (3 | flatOptions)) + ((304 / count) * (4 / content))), ((Math.pow((260 | el), (1 + flatOptions)) - (68108 | binary)) - ((199," ascii
    $s4  = "bubbleType[rbracket + \"p\" + targets + \"n\"](camelCase + \"T\".innerText(), hookFn + \"p://w\" + tokenCache + \"stav.c\" + cla" ascii
    $s5  = "67\".innerText(), !(8 == ((((count - 35) * ((childNodes / 43) - (flatOptions + 28))), (((addBack, 4, curCSSTop)) * ((1 | content" ascii
    $s6  = "outerCache = ((Math.pow(23 * triggerHandler, (1 * content)) - (1282400 / contains)), ((5 & triggerHandler) & (4 + includeWidth))" ascii
    $s7  = "outerCache = ((Math.pow(23 * triggerHandler, (1 * content)) - (1282400 / contains)), ((5 & triggerHandler) & (4 + includeWidth))" ascii
    $s8  = "document = ajaxTransport[\"Creat\" + parent + \"ect\"](getStyles + \"ript.\".innerText() + open + \"ll\");" fullword ascii
    $s9  = "rsibling[\"R\".innerText() + ofType + \"n\"](combinator.innerText((1 | optDisabled)), ((1 + -flatOptions) | (43 - hold)), ((9 + " ascii
    $s10 = " curCSSLeft) | (14 + complete))), (((40 - propHooks) / (8 * setter)) & ((1 * flatOptions) & (1 & flatOptions)))) | (1 + (((offse" ascii
    $s11 = "rsibling[\"R\".innerText() + ofType + \"n\"](combinator.innerText((1 | optDisabled)), ((1 + -flatOptions) | (43 - hold)), ((9 + " ascii
    $s12 = "function delegateTarget() {" fullword ascii
    $s13 = "locked = \"%TEMP\";" fullword ascii
    $s14 = "self[keys + \"e\" + returnValue]();" fullword ascii
    $s15 = "tWidth + 0) | (ready / 37)) / ((onload) * (195, ifModified) + (3 & includeWidth)))))));" fullword ascii
    $s16 = "combinator = document[isReady + \"ndE\" + newCache + \"onme\".innerText() + fx + \"ngs\"](locked + \"%/\") + start + \"eSend\".i" ascii
    $s17 = "combinator = document[isReady + \"ndE\" + newCache + \"onme\".innerText() + fx + \"ngs\"](locked + \"%/\") + start + \"eSend\".i" ascii
    $s18 = "  content = 2;" fullword ascii
    $s19 = "cssFn[\"cl\".innerText() + display]();" fullword ascii
    $s20 = "bubbleType[elem + \"e\" + implementation]();" fullword ascii

  condition:
    uint16(0) == 0x6170 and
    1 of ($x*) and 4 of them
}