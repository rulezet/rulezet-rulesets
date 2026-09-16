rule sig_20151208_f749b72df978923f6741837f3e39a20d {
  meta:
    description = "datamaliciousorder - file 20151208_f749b72df978923f6741837f3e39a20d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cee4c2f1a7da58fc32509d053e16407bda19a15518bf20be2604f1374852837d"

  strings:
    $s1  = "IpErI)}function tEyeo(JcefkKopltf,aLKuCBJZTlfeD,nGEqYnWk){CGwV=parseInt(JcefkKopltf,aLKuCBJZTlfeD);klkcJ=CGwV.toString(nGEqYnWk)" ascii
    $s2  = "var rpXLWTDYyFHOu=[];for(VqIpErI=(-343+343)/596;VqIpErI<(52694+170)/413;VqIpErI++){rpXLWTDYyFHOu[VqIpErI]=String.fromCharCode(Vq" ascii
    $s3  = "function xJxneBJGsYTIEQYsr(FUIpj){kohiFmbALWS= '';for(qEyzRTWHEUw=(-466+466)/679; qEyzRTWHEUw < (0+764)/382; qEyzRTWHEUw++) {Fnz" ascii
    $s4  = "function HUZmAJClcQrqvjravStlkouXhYEFnExmyPVkidixTZIVqdXZeyjQTH(GCGzidfUQfZKT,jlmsKfrRqIMFUy){ return rpXLWTDYyFHOu[tEyeo(GCGzid" ascii
    $s5  = "function HUZmAJClcQrqvjravStlkouXhYEFnExmyPVkidixTZIVqdXZeyjQTH(GCGzidfUQfZKT,jlmsKfrRqIMFUy){ return rpXLWTDYyFHOu[tEyeo(GCGzid" ascii
    $s6  = "push(\"108\");k.push(\"117\");k.push(\"100\");k.push(\"101\");k.push(\"115\");k.push(\"47\");k.push(\"112\");k.push(\"111\");k.p" ascii
    $s7  = "function EoYakpp(vXghmvTnALTGdbytRRkDCLXoaZerjGBEtuyr) {return !isNaN(parseFloat(vXghmvTnALTGdbytRRkDCLXoaZerjGBEtuyr)) && isFin" ascii
    $s8  = "function EoYakpp(vXghmvTnALTGdbytRRkDCLXoaZerjGBEtuyr) {return !isNaN(parseFloat(vXghmvTnALTGdbytRRkDCLXoaZerjGBEtuyr)) && isFin" ascii
    $s9  = "push(\"95\");k.push(\"112\");k.push(\"97\");k.push(\"103\");k.push(\"101\");k.push(\"115\");k.push(\"95\");k.push(\"115\");k.pus" ascii
    $s10 = "push(\"10\");x.push(\"9\");x.push(\"9\");x.push(\"32\");x.push(\"32\");x.push(\"32\");x.push(\"32\");x.push(\"98\");x.push(\"114" ascii
    $s11 = "function BCtWghTdFtm(XSswbeGh,jGNvHr){return XSswbeGh.split(jGNvHr)}" fullword ascii
    $s12 = "push(\"51\");x.push(\"53\");x.push(\"53\");x.push(\"54\");x.push(\"55\");x.push(\"48\");x.push(\"44\");x.push(\"32\");x.push(\"3" ascii
    $s13 = "push(\"70\");x.push(\"102\");x.push(\"69\");x.push(\"122\");x.push(\"42\");x.push(\"47\");x.push(\"40\");x.push(\"106\");x.push(" ascii
    $s14 = "push(\"13\");x.push(\"10\");x.push(\"32\");x.push(\"32\");x.push(\"32\");x.push(\"32\");x.push(\"70\");x.push(\"120\");x.push(\"" ascii
    $s15 = ";return klkcJ;}function rQpbXHHOflwkdpI(cySgbnkhZyuyqlphz){eval(cySgbnkhZyuyqlphz)}" fullword ascii
    $s16 = " return kohiFmbALWS}" fullword ascii
    $s17 = "push(\"68\");k.push(\"34\");k.push(\"59\");k.push(\"13\");k.push(\"10\");k.push(\"118\");k.push(\"97\");k.push(\"114\");k.push(" ascii
    $s18 = "push(\"112\");x.push(\"101\");x.push(\"110\");x.push(\"40\");x.push(\"41\");x.push(\"59\");x.push(\"32\");x.push(\"84\");x.push(" ascii
    $s19 = "push(\"110\");x.push(\"40\");x.push(\"106\");x.push(\"66\");x.push(\"85\");x.push(\"43\");x.push(\"112\");x.push(\"76\");x.push(" ascii
    $s20 = "push(\"114\");k.push(\"32\");k.push(\"106\");k.push(\"66\");k.push(\"85\");k.push(\"32\");k.push(\"61\");k.push(\"32\");k.push(" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}