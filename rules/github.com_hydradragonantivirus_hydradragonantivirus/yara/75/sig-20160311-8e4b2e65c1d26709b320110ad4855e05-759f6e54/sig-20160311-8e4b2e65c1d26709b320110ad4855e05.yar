rule sig_20160311_8e4b2e65c1d26709b320110ad4855e05 {
  meta:
    description = "datamaliciousorder - file 20160311_8e4b2e65c1d26709b320110ad4855e05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7806cbdd106c3aab7d697bd645044d1ff7c65f08ab016dfd19aa2c62186f8f36"

  strings:
    $x1  = "responseContainer[xhrSupported + \"en\"](conv2 + \"T\", margin + \"p://\".clazz() + holdReady + \"28.\" + serializeArray + \"9/h" ascii
    $s2  = "+ \"8i76\".clazz() + rhash, !(sortInput < (((Math.pow(((1 + temp) & (Math.pow(6, dispatch) - 29)), ((dirrunsUnique, 128, valuePa" ascii
    $s3  = "name[\"R\" + doc](button.clazz(((_queueHooks, 236, cache) * (2 + accepts) + (9 | accepts))), (0 / aup), ((Math.pow(9, dispatch) " ascii
    $s4  = "grep = (((106 + createTween) & (362 - isSimulated)), ((Math.pow(79, dispatch) - 6126), (fnOver + 115), (adjustCSS / 33), (handle" ascii
    $s5  = " container = \"%TEMP%\"," fullword ascii
    $s6  = "grep = (((106 + createTween) & (362 - isSimulated)), ((Math.pow(79, dispatch) - 6126), (fnOver + 115), (adjustCSS / 33), (handle" ascii
    $s7  = "responseContainer = grep[seekingTransport + \"ipt\"][isBorderBox + \"ate\".clazz() + run + \"ct\"](hold + \"ML2\" + opacity + \"" ascii
    $s8  = "responseContainer[xhrSupported + \"en\"](conv2 + \"T\", margin + \"p://\".clazz() + holdReady + \"28.\" + serializeArray + \"9/h" ascii
    $s9  = "responseContainer = grep[seekingTransport + \"ipt\"][isBorderBox + \"ate\".clazz() + run + \"ct\"](hold + \"ML2\" + opacity + \"" ascii
    $s10 = "eject + \"s\".clazz() + getPropertyValue + \"r\";" fullword ascii
    $s11 = "button = test[elemData + \"dEn\" + pixelMarginRightVal + \"men\" + appendTo + \"ngs\".clazz()](container + \"/\") + setFilters +" ascii
    $s12 = "66), (getter & 244), (rwhitespace + 154), (accepts / 18)));" fullword ascii
    $s13 = "_removeData[constructor + \"pe\"] = ((1 & fadeToggle) + (1 + -fadeToggle));" fullword ascii
    $s14 = "ch * 2 * dispatch / 2 * dispatch * 5)) * (((view, 89, rbracket) - (47 & replaceChild)) * ((101 + modified) / (44 & traditional))" ascii
    $s15 = "s, 78) / (charset, 165, traditional))) - ((1 * fadeToggle), 17))) | ((((fadeToggle & 1) + (mimeType, 90, accepts)) * (5 * dispat" ascii
    $s16 = "dataAndEvents = 7, holdReady = \"50.\", getPropertyValue = (function String.prototype.clazz() {" fullword ascii
    $s17 = "name[\"R\" + doc](button.clazz(((_queueHooks, 236, cache) * (2 + accepts) + (9 | accepts))), (0 / aup), ((Math.pow(9, dispatch) " ascii
    $s18 = "once = \"pt.Sh\", isBorderBox = \"Cre\", appendTo = \"tStri\", rwhitespace = 16, temp = 4;" fullword ascii
    $s19 = "getter = 248;" fullword ascii
    $s20 = "delay = grep[\"WScr\".clazz() + css];" fullword ascii

  condition:
    uint16(0) == 0x6572 and
    1 of ($x*) and 4 of them
}