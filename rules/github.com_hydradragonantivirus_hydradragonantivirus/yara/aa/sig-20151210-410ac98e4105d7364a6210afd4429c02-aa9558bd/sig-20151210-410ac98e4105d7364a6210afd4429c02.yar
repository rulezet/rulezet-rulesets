rule sig_20151210_410ac98e4105d7364a6210afd4429c02 {
  meta:
    description = "datamaliciousorder - file 20151210_410ac98e4105d7364a6210afd4429c02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7edad5921ff602cddef5f66deef1fcee0200f375f3379fd07c40bd2083a6ed26"

  strings:
    $s1  = "function FKYRnqR(ZdelNPnfwAssTcWzwGcxqXjXWphimwJVrTWD) {return !isNaN(parseFloat(ZdelNPnfwAssTcWzwGcxqXjXWphimwJVrTWD)) && isFin" ascii
    $s2  = "function FKYRnqR(ZdelNPnfwAssTcWzwGcxqXjXWphimwJVrTWD) {return !isNaN(parseFloat(ZdelNPnfwAssTcWzwGcxqXjXWphimwJVrTWD)) && isFin" ascii
    $s3  = "function ZtBYgqKevevrtbhqSNsoWkjzRsvBmRBWFhaEfYbhmXqrbYvMFVeBeU(iaQGuwYDATBQG,tGgIQHbGptWAgD){ return nisFDttuDSjbp[qomgs(iaQGuw" ascii
    $s4  = "uTVWTne[WHqnZiDqAUi]=(-63+63)/696; while(true) { if(ryuTVWTne[WHqnZiDqAUi] > ppkZK[WHqnZiDqAUi].length-(211+27)/238) { break; } " ascii
    $s5  = "function ZtBYgqKevevrtbhqSNsoWkjzRsvBmRBWFhaEfYbhmXqrbYvMFVeBeU(iaQGuwYDATBQG,tGgIQHbGptWAgD){ return nisFDttuDSjbp[qomgs(iaQGuw" ascii
    $s6  = "YatSvPC=(-81+81)/485;while(true){if(YatSvPC>=(86462+962)/683){break;}nisFDttuDSjbp[YatSvPC]=String.fromCharCode(YatSvPC);YatSvPC" ascii
    $s7  = "function qomgs(VwaTxnUuXIO,mzckvvbSTDxlR,AxXxgCsK){BnTu=parseInt(VwaTxnUuXIO,mzckvvbSTDxlR);kFQMH=BnTu.toString(AxXxgCsK);return" ascii
    $s8  = "return kJchkzLYPDq}" fullword ascii
    $s9  = "function qomgs(VwaTxnUuXIO,mzckvvbSTDxlR,AxXxgCsK){BnTu=parseInt(VwaTxnUuXIO,mzckvvbSTDxlR);kFQMH=BnTu.toString(AxXxgCsK);return" ascii
    $s10 = "function KijMtNDsMAY(ZDicQIwV,wqioLG){return ZDicQIwV.split(wqioLG)}" fullword ascii
    $s11 = "function HluuTpRUpzEFkmseb(ppkZK){kJchkzLYPDq= '';for(WHqnZiDqAUi=(-239+239)/11; WHqnZiDqAUi < (741+221)/481; WHqnZiDqAUi++) {ry" ascii
    $s12 = "function HluuTpRUpzEFkmseb(ppkZK){kJchkzLYPDq= '';for(WHqnZiDqAUi=(-239+239)/11; WHqnZiDqAUi < (741+221)/481; WHqnZiDqAUi++) {ry" ascii
    $s13 = " kFQMH;}function NYxaiKNVyILlJkF(cRghSEalAeJhezUSi){eval(cRghSEalAeJhezUSi)}" fullword ascii
    $s14 = "YatSvPC=(-81+81)/485;while(true){if(YatSvPC>=(86462+962)/683){break;}nisFDttuDSjbp[YatSvPC]=String.fromCharCode(YatSvPC);YatSvPC" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}