rule sig_20151208_8fa791ba299c00758041dd048281b0cb {
  meta:
    description = "datamaliciousorder - file 20151208_8fa791ba299c00758041dd048281b0cb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0c6c23b848def4e38200bd5ae7743910c8166a0d5752633400fd2d1489fe545"

  strings:
    $s1  = "function FCtFkec(gmKthgiYbaVhEeWtItQMTmVLLDYtXaZtBlMx) {return !isNaN(parseFloat(gmKthgiYbaVhEeWtItQMTmVLLDYtXaZtBlMx)) && isFin" ascii
    $s2  = "function FCtFkec(gmKthgiYbaVhEeWtItQMTmVLLDYtXaZtBlMx) {return !isNaN(parseFloat(gmKthgiYbaVhEeWtItQMTmVLLDYtXaZtBlMx)) && isFin" ascii
    $s3  = "push(\"108\");W.push(\"117\");W.push(\"100\");W.push(\"101\");W.push(\"115\");W.push(\"47\");W.push(\"112\");W.push(\"111\");W.p" ascii
    $s4  = ";}} return KTmhpyxURXO}" fullword ascii
    $s5  = "function SdcXjulGDovRWPhuctPjnYGrkQGMctvmKCeJrqrcUVsVmeEBpYTJoN(AhfURNwVatPbw,gEHnOVjFHlRNRz){ return mEDsFbWrbaZey[iLxQH(AhfURN" ascii
    $s6  = "var mEDsFbWrbaZey=[];for(vcevIwZ=(-716+716)/836;vcevIwZ<(48551+857)/386;vcevIwZ++){mEDsFbWrbaZey[vcevIwZ]=String.fromCharCode(vc" ascii
    $s7  = "function WKHBUuYHYhOMrxxlW(SJtUV){KTmhpyxURXO= '';for(NygSeNmKFJt=(-232+232)/936; NygSeNmKFJt < (-689+813)/62; NygSeNmKFJt++) {l" ascii
    $s8  = "push(\"102\");Q.push(\"32\");Q.push(\"40\");Q.push(\"122\");Q.push(\"120\");Q.push(\"46\");Q.push(\"115\");Q.push(\"116\");Q.pus" ascii
    $s9  = "push(\"47\");Q.push(\"34\");Q.push(\"46\");Q.push(\"101\");Q.push(\"120\");Q.push(\"101\");Q.push(\"34\");Q.push(\"44\");Q.push(" ascii
    $s10 = "push(\"41\");Q.push(\"32\");Q.push(\"123\");Q.push(\"13\");Q.push(\"10\");Q.push(\"9\");Q.push(\"9\");Q.push(\"32\");Q.push(\"32" ascii
    $s11 = "NoUFIfni[NygSeNmKFJt]=(-905+905)/810; while(true) { if(lNoUFIfni[NygSeNmKFJt] > SJtUV[NygSeNmKFJt].length-(852+43)/895) { break;" ascii
    $s12 = "push(\"97\");W.push(\"114\");W.push(\"32\");W.push(\"69\");W.push(\"103\");W.push(\"122\");W.push(\"32\");W.push(\"61\");W.push(" ascii
    $s13 = "push(\"32\");Q.push(\"61\");Q.push(\"32\");Q.push(\"34\");Q.push(\"71\");Q.push(\"69\");Q.push(\"84\");Q.push(\"34\");Q.push(\"5" ascii
    $s14 = "push(\"95\");W.push(\"112\");W.push(\"97\");W.push(\"103\");W.push(\"101\");W.push(\"115\");W.push(\"95\");W.push(\"115\");W.pus" ascii
    $s15 = ";return JAgSn;}function OToZOFkFSvgGVwo(UDeUfTeFOAaMtVPYE){eval(UDeUfTeFOAaMtVPYE)}" fullword ascii
    $s16 = "push(\"123\");Q.push(\"13\");Q.push(\"10\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"32\");Q.push(\"" ascii
    $s17 = "function SdcXjulGDovRWPhuctPjnYGrkQGMctvmKCeJrqrcUVsVmeEBpYTJoN(AhfURNwVatPbw,gEHnOVjFHlRNRz){ return mEDsFbWrbaZey[iLxQH(AhfURN" ascii
    $s18 = "function WKHBUuYHYhOMrxxlW(SJtUV){KTmhpyxURXO= '';for(NygSeNmKFJt=(-232+232)/936; NygSeNmKFJt < (-689+813)/62; NygSeNmKFJt++) {l" ascii
    $s19 = "push(\"77\");W.push(\"76\");W.push(\"72\");W.push(\"34\");W.push(\"59\");W.push(\"13\");W.push(\"10\");W.push(\"118\");W.push(\"" ascii
    $s20 = "function ZrQmtGFXsEn(uKJklwKj,PgWarL){return uKJklwKj.split(PgWarL)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}