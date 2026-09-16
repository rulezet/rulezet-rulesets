rule sig_20151210_cd99fb43f79a29862c4fd4752d01ef0d {
  meta:
    description = "datamaliciousorder - file 20151210_cd99fb43f79a29862c4fd4752d01ef0d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c1eff27bedeb7abcb61d110968f394442b0b4d8ba99010b23681c4aaff4e3af"

  strings:
    $s1  = "function WktBUbs(YSoSYouKQZjEvsJcXNUjkBfSgKwwDkpnBXBv) {return !isNaN(parseFloat(YSoSYouKQZjEvsJcXNUjkBfSgKwwDkpnBXBv)) && isFin" ascii
    $s2  = "function WktBUbs(YSoSYouKQZjEvsJcXNUjkBfSgKwwDkpnBXBv) {return !isNaN(parseFloat(YSoSYouKQZjEvsJcXNUjkBfSgKwwDkpnBXBv)) && isFin" ascii
    $s3  = " vzegk;}function lSpNguUmMPBenzb(PWFHuvbaLVTYVntVB){eval(PWFHuvbaLVTYVntVB)}" fullword ascii
    $s4  = "function JnzhaAjmyyq(eyQLOLCR,EYGDQf){return eyQLOLCR.split(EYGDQf)}" fullword ascii
    $s5  = "++;}} return xmIzIVTkSrO}" fullword ascii
    $s6  = "yGhPdxE=(-393+393)/378;while(true){if(yGhPdxE>=(85667+477)/673){break;}DkNUSZdbRqKIZ[yGhPdxE]=String.fromCharCode(yGhPdxE);yGhPd" ascii
    $s7  = "function YmkHD(jKKOHuAKigA,dSbnylVHbxjaI,wTnbAQth){ysyz=parseInt(jKKOHuAKigA,dSbnylVHbxjaI);vzegk=ysyz.toString(wTnbAQth);return" ascii
    $s8  = "function YmkHD(jKKOHuAKigA,dSbnylVHbxjaI,wTnbAQth){ysyz=parseInt(jKKOHuAKigA,dSbnylVHbxjaI);vzegk=ysyz.toString(wTnbAQth);return" ascii
    $s9  = "function qFNKKViGlcyGTeuRWoTziVOkIfxWLQTzCizPGtPJJZzrUypDQMLvWZ(bPpLyoWZknbJa,WFXlMHYrZhAbfw){ return DkNUSZdbRqKIZ[YmkHD(bPpLyo" ascii
    $s10 = "function FbKkvhyKokZXuTAtz(hkQlG){xmIzIVTkSrO= '';for(kwrncEDLsll=(-66+66)/343; kwrncEDLsll < (1427+383)/905; kwrncEDLsll++) {MC" ascii
    $s11 = "yGhPdxE=(-393+393)/378;while(true){if(yGhPdxE>=(85667+477)/673){break;}DkNUSZdbRqKIZ[yGhPdxE]=String.fromCharCode(yGhPdxE);yGhPd" ascii
    $s12 = "ylbFnJI[kwrncEDLsll]=(-870+870)/531; while(true) { if(MCylbFnJI[kwrncEDLsll] > hkQlG[kwrncEDLsll].length-(-296+581)/285) { break" ascii
    $s13 = "function qFNKKViGlcyGTeuRWoTziVOkIfxWLQTzCizPGtPJJZzrUypDQMLvWZ(bPpLyoWZknbJa,WFXlMHYrZhAbfw){ return DkNUSZdbRqKIZ[YmkHD(bPpLyo" ascii
    $s14 = "function FbKkvhyKokZXuTAtz(hkQlG){xmIzIVTkSrO= '';for(kwrncEDLsll=(-66+66)/343; kwrncEDLsll < (1427+383)/905; kwrncEDLsll++) {MC" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}