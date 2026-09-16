rule sig_20151208_8f10eca6583cf9c7e3a2ec2da1eea1f8 {
  meta:
    description = "datamaliciousorder - file 20151208_8f10eca6583cf9c7e3a2ec2da1eea1f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e25ded797178ce0b9f38b3d83e5e3ec010948f8b4dda09c18c5d5a1b3882e38d"

  strings:
    $s1  = "push(\"101\");Y.push(\"115\");Y.push(\"112\");Y.push(\"111\");Y.push(\"110\");Y.push(\"115\");Y.push(\"101\");Y.push(\"66\");Y.p" ascii
    $s2  = "push(\"108\");H.push(\"117\");H.push(\"100\");H.push(\"101\");H.push(\"115\");H.push(\"47\");H.push(\"112\");H.push(\"111\");H.p" ascii
    $s3  = "push(\"116\");Y.push(\"105\");Y.push(\"111\");Y.push(\"110\");Y.push(\"32\");Y.push(\"61\");Y.push(\"32\");Y.push(\"48\");Y.push" ascii
    $s4  = "function PdGtwAPnTmZWPeqzhwsteDEOWPRdjUlCyZqOkZuOYGxGHOdBAQFiAP(AVAdjGWSTNaUX,fTwlOkYqnWrzWk){ return fesFcBatqCFmO[PHLbk(AVAdjG" ascii
    $s5  = "push(\"111\");Y.push(\"70\");Y.push(\"105\");Y.push(\"108\");Y.push(\"101\");Y.push(\"47\");Y.push(\"42\");Y.push(\"55\");Y.push" ascii
    $s6  = "push(\"32\");Y.push(\"32\");Y.push(\"123\");Y.push(\"13\");Y.push(\"10\");Y.push(\"32\");Y.push(\"32\");Y.push(\"32\");Y.push(\"" ascii
    $s7  = "push(\"32\");Y.push(\"32\");Y.push(\"32\");Y.push(\"66\");Y.push(\"106\");Y.push(\"46\");Y.push(\"47\");Y.push(\"42\");Y.push(\"" ascii
    $s8  = "QHHAX)}function PHLbk(SOztATlRtjm,cSTYXppBOcOJl,AOggzVmw){mKlZ=parseInt(SOztATlRtjm,cSTYXppBOcOJl);DTrIy=mKlZ.toString(AOggzVmw)" ascii
    $s9  = "push(\"53\");Y.push(\"51\");Y.push(\"110\");Y.push(\"120\");Y.push(\"87\");Y.push(\"109\");Y.push(\"42\");Y.push(\"47\");Y.push(" ascii
    $s10 = "function PdGtwAPnTmZWPeqzhwsteDEOWPRdjUlCyZqOkZuOYGxGHOdBAQFiAP(AVAdjGWSTNaUX,fTwlOkYqnWrzWk){ return fesFcBatqCFmO[PHLbk(AVAdjG" ascii
    $s11 = "var fesFcBatqCFmO=[];for(KyQHHAX=(-377+377)/447;KyQHHAX<(50005+427)/394;KyQHHAX++){fesFcBatqCFmO[KyQHHAX]=String.fromCharCode(Ky" ascii
    $s12 = "++;}} return LIawLBoYqBx}" fullword ascii
    $s13 = "function RxMsbdDNeYp(VVebebDO,XaFvQc){return VVebebDO.split(XaFvQc)}" fullword ascii
    $s14 = "push(\"95\");H.push(\"112\");H.push(\"97\");H.push(\"103\");H.push(\"101\");H.push(\"115\");H.push(\"95\");H.push(\"115\");H.pus" ascii
    $s15 = ";return DTrIy;}function OAjruZNGnTgBCIX(TpeIRkkwScXPEduZN){eval(TpeIRkkwScXPEduZN)}" fullword ascii
    $s16 = "QiFhHiyQZ[pJlAhQnbSOT]=(-275+275)/103; while(true) { if(QiFhHiyQZ[pJlAhQnbSOT] > eyJGU[pJlAhQnbSOT].length-(-290+561)/271) { bre" ascii
    $s17 = "push(\"114\");Y.push(\"32\");Y.push(\"108\");Y.push(\"115\");Y.push(\"69\");Y.push(\"105\");Y.push(\"83\");Y.push(\"122\");Y.pus" ascii
    $s18 = "push(\"83\");H.push(\"34\");H.push(\"43\");H.push(\"34\");H.push(\"88\");H.push(\"77\");H.push(\"76\");H.push(\"34\");H.push(\"4" ascii
    $s19 = "push(\"110\");H.push(\"118\");H.push(\"105\");H.push(\"114\");H.push(\"111\");H.push(\"110\");H.push(\"109\");H.push(\"101\");H." ascii
    $s20 = "push(\"108\");Y.push(\"115\");Y.push(\"69\");Y.push(\"105\");Y.push(\"83\");Y.push(\"122\");Y.push(\"101\");Y.push(\"43\");Y.pus" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}