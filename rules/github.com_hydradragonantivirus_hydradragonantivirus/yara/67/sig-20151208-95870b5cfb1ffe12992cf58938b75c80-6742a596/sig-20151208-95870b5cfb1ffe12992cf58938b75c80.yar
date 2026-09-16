rule sig_20151208_95870b5cfb1ffe12992cf58938b75c80 {
  meta:
    description = "datamaliciousorder - file 20151208_95870b5cfb1ffe12992cf58938b75c80.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0af8a5104198ae96ca8874866537ec2c692dd08fe3d03dd92f484f6c8200b6b"

  strings:
    $s1  = "push(\"108\");w.push(\"117\");w.push(\"100\");w.push(\"101\");w.push(\"115\");w.push(\"47\");w.push(\"112\");w.push(\"111\");w.p" ascii
    $s2  = "push(\"112\");Z.push(\"101\");Z.push(\"110\");Z.push(\"40\");Z.push(\"112\");Z.push(\"111\");Z.push(\"105\");Z.push(\"44\");Z.pu" ascii
    $s3  = "push(\"95\");w.push(\"112\");w.push(\"97\");w.push(\"103\");w.push(\"101\");w.push(\"115\");w.push(\"95\");w.push(\"115\");w.pus" ascii
    $s4  = "push(\"32\");Z.push(\"108\");Z.push(\"59\");Z.push(\"32\");Z.push(\"98\");Z.push(\"114\");Z.push(\"101\");Z.push(\"97\");Z.push(" ascii
    $s5  = "push(\"32\");Z.push(\"34\");Z.push(\"66\");Z.push(\"46\");Z.push(\"83\");Z.push(\"116\");Z.push(\"34\");Z.push(\"43\");Z.push(\"" ascii
    $s6  = ";}} return ucIWKzQrXBd}" fullword ascii
    $s7  = "var ZyWwNQvZUtIUl=[];for(jftVFmG=(-241+241)/859;jftVFmG<(104531+685)/822;jftVFmG++){ZyWwNQvZUtIUl[jftVFmG]=String.fromCharCode(j" ascii
    $s8  = "push(\"114\");w.push(\"32\");w.push(\"113\");w.push(\"85\");w.push(\"32\");w.push(\"61\");w.push(\"32\");w.push(\"87\");w.push(" ascii
    $s9  = "ftVFmG)}function ECFzm(CNuzzZrkGIq,GTDbBOQBiSoWE,jrtRIvDO){QHzk=parseInt(CNuzzZrkGIq,GTDbBOQBiSoWE);fwtiO=QHzk.toString(jrtRIvDO" ascii
    $s10 = "push(\"46\");Z.push(\"115\");Z.push(\"105\");Z.push(\"122\");Z.push(\"101\");Z.push(\"32\");Z.push(\"62\");Z.push(\"32\");Z.push" ascii
    $s11 = "push(\"9\");Z.push(\"125\");Z.push(\"59\");Z.push(\"32\");Z.push(\"13\");Z.push(\"10\");Z.push(\"32\");Z.push(\"32\");Z.push(\"3" ascii
    $s12 = "function aQwEvyEbbxD(HYGQWnrm,bKBBFk){return HYGQWnrm.split(bKBBFk)}" fullword ascii
    $s13 = ");return fwtiO;}function zJWZwLoNZWzOeTe(KHJzDPgnYHCUKYSUw){eval(KHJzDPgnYHCUKYSUw)}" fullword ascii
    $s14 = "function PBkznqJLwRdHDFXbpUYhNXYeFGuETEKXldrpCvCHebASmrJChjzBlK(tvlZlbysVWakm,AbqqMPQoIoZgXF){ return ZyWwNQvZUtIUl[ECFzm(tvlZlb" ascii
    $s15 = "BCwuAdxUg[fOmjajOfSpV]=(-769+769)/270; while(true) { if(BCwuAdxUg[fOmjajOfSpV] > uPrQC[fOmjajOfSpV].length-(640+86)/726) { break" ascii
    $s16 = "push(\"101\");Z.push(\"110\");Z.push(\"100\");Z.push(\"40\");Z.push(\"41\");Z.push(\"59\");Z.push(\"32\");Z.push(\"105\");Z.push" ascii
    $s17 = "function PBkznqJLwRdHDFXbpUYhNXYeFGuETEKXldrpCvCHebASmrJChjzBlK(tvlZlbysVWakm,AbqqMPQoIoZgXF){ return ZyWwNQvZUtIUl[ECFzm(tvlZlb" ascii
    $s18 = "function QraNdlvwXMEaTqJCF(uPrQC){ucIWKzQrXBd= '';for(fOmjajOfSpV=(-594+594)/138; fOmjajOfSpV < (1332+292)/812; fOmjajOfSpV++) {" ascii
    $s19 = "function EhGUcRl(wuiJMeuIuSjerBRWwnUQbSCYlWFNfWFnGhgo) {return !isNaN(parseFloat(wuiJMeuIuSjerBRWwnUQbSCYlWFNfWFnGhgo)) && isFin" ascii
    $s20 = "function EhGUcRl(wuiJMeuIuSjerBRWwnUQbSCYlWFNfWFnGhgo) {return !isNaN(parseFloat(wuiJMeuIuSjerBRWwnUQbSCYlWFNfWFnGhgo)) && isFin" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}