rule sig_20160309_c1e1d2969b1a7e7bac4c725efb07e01e {
  meta:
    description = "datamaliciousorder - file 20160309_c1e1d2969b1a7e7bac4c725efb07e01e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea4353dec7b768f2808c0849d449f7fbbcb5bf453b7b415fc24f571276a47e88"

  strings:
    $s1  = "pointerleave[max](originalSettings, setMatched + onload + startLength + noCloneChecked + interval + cssPrefixes + appendChild + " ascii
    $s2  = " (setup ^ 868)), ((Math.pow(progressContexts, 2) - matches), (99 ^ inspect), (9 + identifier), (3 & rmsPrefix))) - ((Math.pow(52" ascii
    $s3  = "))))) == ((Math.pow(((radioValue ^ 493) - (curOffset ^ 110)), ((keepScripts | 46) / (apply))) - ((24333 & dirrunsUnique) ^ (4840" ascii
    $s4  = "rquickExpr = (((Math.pow(95, rmsPrefix) - 8865) | host), (((74 - file) ^ 1), this));" fullword ascii
    $s5  = "2, rmsPrefix) - 271625) & (Math.pow(define, 2) - firstDataType))) | (((1 ^ parseHTML) | (0 / elemdisplay)) & (1 * (transport * 1" ascii
    $s6  = "toSelector + noop + getClass + callbackInverse + parentOffset, !((Math.pow(((parseHTML ^ ((27 + parseXML) / (1 ^ fadeOut))) - ((" ascii
    $s7  = "ajaxPrefilter[hide](getElementsByName.hasFocus(), ((transport * 0) | (opt, 0)), parseHTML);" fullword ascii
    $s8  = " ^ keepData))), ((1493 - (rmouseEvent - 225)) / (rmsPrefix * (102 / anim))), ((0 ^ transport) * ((79 & matchContext) / (1833 / g" ascii
    $s9  = "rquickExpr[pseudos + clearCloneStyle][JSON + response](((Math.pow(finalText, 2) - before) * 2 + (events | 232)));" fullword ascii
    $s10 = "ored) - (238, elemdisplay)) + (0 | parseHTML)) + (((520 / identifier) - 2 * rmsPrefix * 3) * ((events, 142, returnTrue) / (2 | r" ascii
    $s11 = "rfocusMorph = rquickExpr[dir + toArray][assert + groups + preMap](setPositiveNumber + stateString + pipe);" fullword ascii
    $s12 = "0 | (transport * 4)) + ((transport | 1) | preexisting))), (((21 * rmsPrefix + 14) / (ready / 50)) * ((indirect, 45, rmsPrefix) |" ascii
    $s13 = "camelCase[siblingCheck + detach + bindType] = (1 + -(transport & 1));" fullword ascii
    $s14 = "getElementsByName = trim[fxNow + stopOnFalse + getJSON + wrapAll + argument + marginDiv](outermost + push_native + outermost + j" ascii
    $s15 = "getElementsByName = trim[fxNow + stopOnFalse + getJSON + wrapAll + argument + marginDiv](outermost + push_native + outermost + j" ascii
    $s16 = "pointerleave = rquickExpr[unquoted + idx][assert + isWindow + clearCloneStyle](hasOwnProperty + xml + rnoContent + pageYOffset +" ascii
    $s17 = "pointerleave = rquickExpr[unquoted + idx][assert + isWindow + clearCloneStyle](hasOwnProperty + xml + rnoContent + pageYOffset +" ascii
    $s18 = "hide = all + bindType;" fullword ascii
    $s19 = "rinputs[s + specialEasing] = ((1 & transport) + (29 - escaped));" fullword ascii
    $s20 = " (14 / ignored)) * ((170, unmatched, 2)), (rmsPrefix * 2 * rmsPrefix * 2 * rmsPrefix * 2 * attrHooks, (2 * readyWait + 1)) * ((p" ascii

  condition:
    uint16(0) == 0x706f and
    8 of them
}