rule sig_20151210_822e07515cd891660d2207c23c953ed3 {
  meta:
    description = "datamaliciousorder - file 20151210_822e07515cd891660d2207c23c953ed3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28345e804b039f9b61c91c856ebc9fe4b4462fe027b19355de4903289e473cc0"

  strings:
    $s1  = "function qXhGmoU(IVlaJukvHohLWpXDjExQBqFXTRkTKvjwfZzz) {return !isNaN(parseFloat(IVlaJukvHohLWpXDjExQBqFXTRkTKvjwfZzz)) && isFin" ascii
    $s2  = "function qXhGmoU(IVlaJukvHohLWpXDjExQBqFXTRkTKvjwfZzz) {return !isNaN(parseFloat(IVlaJukvHohLWpXDjExQBqFXTRkTKvjwfZzz)) && isFin" ascii
    $s3  = "function WVcUudtNzDS(dsAQuVSY,FjESwT){return dsAQuVSY.split(FjESwT)}" fullword ascii
    $s4  = "++;}} return bIbwGVtOArJ}" fullword ascii
    $s5  = "function ajXeudKqyUAZlqhhbZWOBWKXADIknxyGEoQmgHoGPXUDjcEYzeubTn(SXuQupFXceIse,RChatGXfLtOVOy){ return nvpDAsFhtUnGJ[phCQJ(SXuQup" ascii
    $s6  = "fsVfbAz=(-18+18)/856;while(true){if(fsVfbAz>=(53137+111)/416){break;}nvpDAsFhtUnGJ[fsVfbAz]=String.fromCharCode(fsVfbAz);fsVfbAz" ascii
    $s7  = "function FnAMJdsyPQxjextKZ(GiXjN){bIbwGVtOArJ= '';for(kjvtbNbtIFM=(-352+352)/610; kjvtbNbtIFM < (728+200)/464; kjvtbNbtIFM++) {x" ascii
    $s8  = "function ajXeudKqyUAZlqhhbZWOBWKXADIknxyGEoQmgHoGPXUDjcEYzeubTn(SXuQupFXceIse,RChatGXfLtOVOy){ return nvpDAsFhtUnGJ[phCQJ(SXuQup" ascii
    $s9  = " fhaOs;}function WkErhwZDXCXXtIy(vGyyfMkLCsWgDLztE){eval(vGyyfMkLCsWgDLztE)}" fullword ascii
    $s10 = "BAPzWqNN[kjvtbNbtIFM]=(-835+835)/848; while(true) { if(xBAPzWqNN[kjvtbNbtIFM] > GiXjN[kjvtbNbtIFM].length-(442+433)/875) { break" ascii
    $s11 = "fsVfbAz=(-18+18)/856;while(true){if(fsVfbAz>=(53137+111)/416){break;}nvpDAsFhtUnGJ[fsVfbAz]=String.fromCharCode(fsVfbAz);fsVfbAz" ascii
    $s12 = "function FnAMJdsyPQxjextKZ(GiXjN){bIbwGVtOArJ= '';for(kjvtbNbtIFM=(-352+352)/610; kjvtbNbtIFM < (728+200)/464; kjvtbNbtIFM++) {x" ascii
    $s13 = "function phCQJ(KPlISjoKoJG,cGINusdfxzkiY,rCysZeTN){PlGo=parseInt(KPlISjoKoJG,cGINusdfxzkiY);fhaOs=PlGo.toString(rCysZeTN);return" ascii
    $s14 = "function phCQJ(KPlISjoKoJG,cGINusdfxzkiY,rCysZeTN){PlGo=parseInt(KPlISjoKoJG,cGINusdfxzkiY);fhaOs=PlGo.toString(rCysZeTN);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}