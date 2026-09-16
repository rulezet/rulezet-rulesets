rule sig_20151208_a7a3f6c692658083fea9e156c4715ea7 {
  meta:
    description = "datamaliciousorder - file 20151208_a7a3f6c692658083fea9e156c4715ea7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a370c8e040303d1dc23c37f85dd2299be7368d5e718e79da9df73b0f477431a6"

  strings:
    $s1  = "function jFgVgGt(JWthZDrSKzoMXUtWJhtWBqRIeZEoBotbDoku) {return !isNaN(parseFloat(JWthZDrSKzoMXUtWJhtWBqRIeZEoBotbDoku)) && isFin" ascii
    $s2  = "function jFgVgGt(JWthZDrSKzoMXUtWJhtWBqRIeZEoBotbDoku) {return !isNaN(parseFloat(JWthZDrSKzoMXUtWJhtWBqRIeZEoBotbDoku)) && isFin" ascii
    $s3  = "push(\"32\");s.push(\"61\");s.push(\"32\");s.push(\"87\");s.push(\"83\");s.push(\"99\");s.push(\"114\");s.push(\"105\");s.push(" ascii
    $s4  = "push(\"32\");j.push(\"32\");j.push(\"32\");j.push(\"32\");j.push(\"32\");j.push(\"32\");j.push(\"81\");j.push(\"112\");j.push(\"" ascii
    $s5  = "function OxkRgXRDglfFvhXLp(cWRSN){NqdJeclRXoW= '';for(XdXLodHvMAd=(-898+898)/558; XdXLodHvMAd < (-584+912)/164; XdXLodHvMAd++) {" ascii
    $s6  = "var ynCubaJuPlMyc=[];for(GkbghzN=(-612+612)/659;GkbghzN<(27194+70)/213;GkbghzN++){ynCubaJuPlMyc[GkbghzN]=String.fromCharCode(Gkb" ascii
    $s7  = "push(\"61\");j.push(\"32\");j.push(\"49\");j.push(\"59\");j.push(\"32\");j.push(\"83\");j.push(\"70\");j.push(\"74\");j.push(\"4" ascii
    $s8  = "push(\"32\");j.push(\"32\");j.push(\"32\");j.push(\"100\");j.push(\"70\");j.push(\"32\");j.push(\"61\");j.push(\"32\");j.push(\"" ascii
    $s9  = "push(\"68\");j.push(\"48\");j.push(\"42\");j.push(\"47\");j.push(\"51\");j.push(\"45\");j.push(\"50\");j.push(\"44\");j.push(\"4" ascii
    $s10 = "return OTieG;}function lXbQqklwZSDsvFy(lCVOwVqimEIQHCcOD){eval(lCVOwVqimEIQHCcOD)}" fullword ascii
    $s11 = "push(\"80\");s.push(\"67\");s.push(\"32\");s.push(\"61\");s.push(\"32\");s.push(\"69\");s.push(\"88\");s.push(\"89\");s.push(\"3" ascii
    $s12 = "push(\"59\");j.push(\"9\");j.push(\"32\");j.push(\"13\");j.push(\"10\");j.push(\"32\");j.push(\"32\");j.push(\"32\");j.push(\"32" ascii
    $s13 = "ghzN)}function tZTMf(vJjQRLLNkaK,RVXrKDhhtIOqQ,jESCBJHJ){wYfM=parseInt(vJjQRLLNkaK,RVXrKDhhtIOqQ);OTieG=wYfM.toString(jESCBJHJ);" ascii
    $s14 = "hCWNlgMoV[XdXLodHvMAd]=(-249+249)/42; while(true) { if(hCWNlgMoV[XdXLodHvMAd] > cWRSN[XdXLodHvMAd].length-(359+226)/585) { break" ascii
    $s15 = "function aZeUJDLFwaA(WxuohQfv,DKtdSN){return WxuohQfv.split(DKtdSN)}" fullword ascii
    $s16 = "+;}} return NqdJeclRXoW}" fullword ascii
    $s17 = "function OxkRgXRDglfFvhXLp(cWRSN){NqdJeclRXoW= '';for(XdXLodHvMAd=(-898+898)/558; XdXLodHvMAd < (-584+912)/164; XdXLodHvMAd++) {" ascii
    $s18 = "function okgaNdqHUSWEXnbtjeGQOcGeGDYpKUCCaDeFDpXugREUPEdhnjbdud(rzckdHbVBpMyv,YSnCRSNSaKkIbe){ return ynCubaJuPlMyc[tZTMf(rzckdH" ascii
    $s19 = "function okgaNdqHUSWEXnbtjeGQOcGeGDYpKUCCaDeFDpXugREUPEdhnjbdud(rzckdHbVBpMyv,YSnCRSNSaKkIbe){ return ynCubaJuPlMyc[tZTMf(rzckdH" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}