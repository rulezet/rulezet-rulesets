rule sig_20151208_66a3724e2b6147068613711456744b23 {
  meta:
    description = "datamaliciousorder - file 20151208_66a3724e2b6147068613711456744b23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51c7c041b8b08caf9e9587d8b3c4b08c353fe90e994de2e55052203a5458ad4a"

  strings:
    $s1  = "function smnvDqe(OHquFquezIIGsROLjhQMjwyvcYUjAfnIUMPc) {return !isNaN(parseFloat(OHquFquezIIGsROLjhQMjwyvcYUjAfnIUMPc)) && isFin" ascii
    $s2  = "function smnvDqe(OHquFquezIIGsROLjhQMjwyvcYUjAfnIUMPc) {return !isNaN(parseFloat(OHquFquezIIGsROLjhQMjwyvcYUjAfnIUMPc)) && isFin" ascii
    $s3  = "function zqTzpHkSSpQrvChZTvmTgSZiQQykdbpTjuTWIInRWNDNjFhVwdESee(YMRBbjTQYCmQk,TztjWhQvhnDESf){ return uKlAItLJexVmz[tXMnY(YMRBbj" ascii
    $s4  = "function zUvVeJapZPXPjrlTn(CcCtz){DmFlccNBCOj= '';for(EPTbfjLnJlm=(-979+979)/264; EPTbfjLnJlm < (1147+619)/883; EPTbfjLnJlm++) {" ascii
    $s5  = "abRGz)}function tXMnY(BhqBpcJBdFd,KmTbsGRkEFkNf,FoPxZMkT){ZWUi=parseInt(BhqBpcJBdFd,KmTbsGRkEFkNf);WgEfS=ZWUi.toString(FoPxZMkT)" ascii
    $s6  = "push(\"108\");e.push(\"111\");e.push(\"115\");e.push(\"101\");e.push(\"40\");e.push(\"41\");e.push(\"59\");e.push(\"32\");e.push" ascii
    $s7  = "push(\"46\");k.push(\"67\");k.push(\"114\");k.push(\"101\");k.push(\"97\");k.push(\"116\");k.push(\"101\");k.push(\"79\");k.push" ascii
    $s8  = "push(\"32\");e.push(\"13\");e.push(\"10\");e.push(\"125\");e.push(\"59\");e.push(\"32\");e.push(\"13\");e.push(\"10\");e.push(\"" ascii
    $s9  = "push(\"61\");k.push(\"32\");k.push(\"34\");k.push(\"50\");k.push(\"46\");k.push(\"88\");k.push(\"77\");k.push(\"76\");k.push(\"7" ascii
    $s10 = "push(\"103\");e.push(\"46\");e.push(\"115\");e.push(\"97\");e.push(\"118\");e.push(\"101\");e.push(\"84\");e.push(\"111\");e.pus" ascii
    $s11 = "push(\"32\");e.push(\"32\");e.push(\"32\");e.push(\"99\");e.push(\"97\");e.push(\"116\");e.push(\"99\");e.push(\"104\");e.push(" ascii
    $s12 = "function zUvVeJapZPXPjrlTn(CcCtz){DmFlccNBCOj= '';for(EPTbfjLnJlm=(-979+979)/264; EPTbfjLnJlm < (1147+619)/883; EPTbfjLnJlm++) {" ascii
    $s13 = "push(\"117\");e.push(\"115\");e.push(\"32\");e.push(\"61\");e.push(\"61\");e.push(\"32\");e.push(\"51\");e.push(\"55\");e.push(" ascii
    $s14 = "function zqTzpHkSSpQrvChZTvmTgSZiQQykdbpTjuTWIInRWNDNjFhVwdESee(YMRBbjTQYCmQk,TztjWhQvhnDESf){ return uKlAItLJexVmz[tXMnY(YMRBbj" ascii
    $s15 = "push(\"47\");k.push(\"42\");k.push(\"89\");k.push(\"89\");k.push(\"72\");k.push(\"85\");k.push(\"50\");k.push(\"51\");k.push(\"5" ascii
    $s16 = "++;}} return DmFlccNBCOj}" fullword ascii
    $s17 = "xGtKQhoqY[EPTbfjLnJlm]=(-766+766)/51; while(true) { if(xGtKQhoqY[EPTbfjLnJlm] > CcCtz[EPTbfjLnJlm].length-(-156+822)/666) { brea" ascii
    $s18 = "push(\"79\");e.push(\"103\");e.push(\"46\");e.push(\"112\");e.push(\"111\");e.push(\"115\");e.push(\"105\");e.push(\"116\");e.pu" ascii
    $s19 = "push(\"114\");k.push(\"32\");k.push(\"76\");k.push(\"85\");k.push(\"32\");k.push(\"61\");k.push(\"32\");k.push(\"116\");k.push(" ascii
    $s20 = ";return WgEfS;}function fooukiujEzEDmpq(tBZAiDUcNgexqkUxD){eval(tBZAiDUcNgexqkUxD)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}