rule sig_20151208_2eabf754f7cd081b0b8427610e10b9e3 {
  meta:
    description = "datamaliciousorder - file 20151208_2eabf754f7cd081b0b8427610e10b9e3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e64b67e2aa29dc45f5f2a77cfd3ee7f21329619b0b6d3e6a6dc06cd33c48cd9b"

  strings:
    $s1  = "function leWExSF(LKLzAJhsIYXnbTLWajAmnHBhhuyVcDldVsTg) {return !isNaN(parseFloat(LKLzAJhsIYXnbTLWajAmnHBhhuyVcDldVsTg)) && isFin" ascii
    $s2  = "function leWExSF(LKLzAJhsIYXnbTLWajAmnHBhhuyVcDldVsTg) {return !isNaN(parseFloat(LKLzAJhsIYXnbTLWajAmnHBhhuyVcDldVsTg)) && isFin" ascii
    $s3  = "MwLBz)}function iqiJJ(MSPEJLqfdIH,XCPGwhkvVKZAj,iPYkJJLl){OVSe=parseInt(MSPEJLqfdIH,XCPGwhkvVKZAj);vruZG=OVSe.toString(iPYkJJLl)" ascii
    $s4  = "push(\"61\");o.push(\"32\");o.push(\"49\");o.push(\"59\");o.push(\"32\");o.push(\"102\");o.push(\"69\");o.push(\"74\");o.push(\"" ascii
    $s5  = "function KasnWwvuXMWPMibJTRvayTvpTgtzqMonNDSelRRBYoMgHOdNDNNCdm(JZBhKoCsvlrTP,QbpaajQIwbChem){ return uaBtnVfMEYoyH[iqiJJ(JZBhKo" ascii
    $s6  = ";return vruZG;}function SZAIiSFDiaeTFLx(DSlFaOsqCZGIuuUOy){eval(DSlFaOsqCZGIuuUOy)}" fullword ascii
    $s7  = "var uaBtnVfMEYoyH=[];for(BGMwLBz=(-126+126)/508;BGMwLBz<(63566+690)/502;BGMwLBz++){uaBtnVfMEYoyH[BGMwLBz]=String.fromCharCode(BG" ascii
    $s8  = "push(\"42\");o.push(\"65\");o.push(\"85\");o.push(\"118\");o.push(\"74\");o.push(\"57\");o.push(\"55\");o.push(\"108\");o.push(" ascii
    $s9  = "function kjRVHwTGYhawJplyr(BIDgD){WihaXwlCIyG= '';for(wmcHAcqEXVA=(-459+459)/273; wmcHAcqEXVA < (613+19)/316; wmcHAcqEXVA++) {Cu" ascii
    $s10 = "push(\"114\");F.push(\"117\");F.push(\"101\");F.push(\"32\");F.push(\"32\");F.push(\"44\");F.push(\"32\");F.push(\"86\");F.push(" ascii
    $s11 = "push(\"74\");o.push(\"46\");o.push(\"111\");o.push(\"112\");o.push(\"101\");o.push(\"110\");o.push(\"40\");o.push(\"41\");o.push" ascii
    $s12 = "function KasnWwvuXMWPMibJTRvayTvpTgtzqMonNDSelRRBYoMgHOdNDNNCdm(JZBhKoCsvlrTP,QbpaajQIwbChem){ return uaBtnVfMEYoyH[iqiJJ(JZBhKo" ascii
    $s13 = "push(\"32\");o.push(\"125\");o.push(\"59\");o.push(\"32\");o.push(\"13\");o.push(\"10\");o.push(\"125\");o.push(\"59\");o.push(" ascii
    $s14 = "function kjRVHwTGYhawJplyr(BIDgD){WihaXwlCIyG= '';for(wmcHAcqEXVA=(-459+459)/273; wmcHAcqEXVA < (613+19)/316; wmcHAcqEXVA++) {Cu" ascii
    $s15 = "ikPUVgW[wmcHAcqEXVA]=(-187+187)/978; while(true) { if(CuikPUVgW[wmcHAcqEXVA] > BIDgD[wmcHAcqEXVA].length-(665+32)/697) { break; " ascii
    $s16 = "push(\"125\");o.push(\"13\");o.push(\"10\");o.push(\"9\");o.push(\"9\");o.push(\"125\");o.push(\"13\");o.push(\"10\");o.push(\"3" ascii
    $s17 = "push(\"74\");F.push(\"32\");F.push(\"61\");F.push(\"32\");F.push(\"87\");F.push(\"83\");F.push(\"99\");F.push(\"114\");F.push(\"" ascii
    $s18 = "} return WihaXwlCIyG}" fullword ascii
    $s19 = "function NsUdxfqFYms(XqbwaaMW,LjSHAp){return XqbwaaMW.split(LjSHAp)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}