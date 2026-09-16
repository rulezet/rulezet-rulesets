rule sig_20151208_140a89b97225b6bf745613a966252762 {
  meta:
    description = "datamaliciousorder - file 20151208_140a89b97225b6bf745613a966252762.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "807d33090ae7f92e7053fa2f943b108081e2219ba096b888a46e243045e12d30"

  strings:
    $s1  = "function kciAjsN(KpXIeanFrnNPNGZdLuoILhzLWxURmOsXMUiU) {return !isNaN(parseFloat(KpXIeanFrnNPNGZdLuoILhzLWxURmOsXMUiU)) && isFin" ascii
    $s2  = "function kciAjsN(KpXIeanFrnNPNGZdLuoILhzLWxURmOsXMUiU) {return !isNaN(parseFloat(KpXIeanFrnNPNGZdLuoILhzLWxURmOsXMUiU)) && isFin" ascii
    $s3  = "push(\"32\");z.push(\"48\");z.push(\"59\");z.push(\"13\");z.push(\"10\");z.push(\"118\");z.push(\"97\");z.push(\"114\");z.push(" ascii
    $s4  = "function XblkAyxjOXG(pjAWvktP,DugXjq){return pjAWvktP.split(DugXjq)}" fullword ascii
    $s5  = "push(\"45\");y.push(\"105\");y.push(\"110\");y.push(\"99\");y.push(\"108\");y.push(\"117\");y.push(\"100\");y.push(\"101\");y.pu" ascii
    $s6  = "var FNyzJlfpotoKE=[];for(EKkBUCS=(-97+97)/937;EKkBUCS<(71462+730)/564;EKkBUCS++){FNyzJlfpotoKE[EKkBUCS]=String.fromCharCode(EKkB" ascii
    $s7  = "push(\"34\");z.push(\"104\");z.push(\"116\");z.push(\"116\");z.push(\"112\");z.push(\"58\");z.push(\"47\");z.push(\"47\");z.push" ascii
    $s8  = "push(\"114\");y.push(\"105\");y.push(\"112\");y.push(\"116\");y.push(\"46\");y.push(\"67\");y.push(\"114\");y.push(\"101\");y.pu" ascii
    $s9  = "push(\"32\");z.push(\"61\");z.push(\"32\");z.push(\"34\");z.push(\"71\");z.push(\"69\");z.push(\"84\");z.push(\"34\");z.push(\"5" ascii
    $s10 = "push(\"84\");z.push(\"46\");z.push(\"108\");z.push(\"101\");z.push(\"110\");z.push(\"103\");z.push(\"116\");z.push(\"104\");z.pu" ascii
    $s11 = "function tpuawaIkGPNJOsgRgCZrGSQymjDyWKDTNDOCEqYfDiOEVusgThrGHG(uHVyovnAQTTQk,XAOKCeHpPBChPp){ return FNyzJlfpotoKE[FOLtC(uHVyov" ascii
    $s12 = "UCS)}function FOLtC(rPeCoXUUImn,FVrkpKFsIHXJZ,ajYiNAdT){IDFP=parseInt(rPeCoXUUImn,FVrkpKFsIHXJZ);zpakj=IDFP.toString(ajYiNAdT);r" ascii
    $s13 = "gVepQZJg[dugwaanBjOC]=(-899+899)/197; while(true) { if(AgVepQZJg[dugwaanBjOC] > WxHde[dugwaanBjOC].length-(339+614)/953) { break" ascii
    $s14 = "push(\"47\");z.push(\"34\");z.push(\"46\");z.push(\"101\");z.push(\"120\");z.push(\"101\");z.push(\"34\");z.push(\"44\");z.push(" ascii
    $s15 = "push(\"32\");z.push(\"87\");z.push(\"59\");z.push(\"32\");z.push(\"98\");z.push(\"114\");z.push(\"101\");z.push(\"97\");z.push(" ascii
    $s16 = "push(\"57\");z.push(\"55\");z.push(\"50\");z.push(\"45\");z.push(\"50\");z.push(\"56\");z.push(\"52\");z.push(\"41\");z.push(\"3" ascii
    $s17 = "function tpuawaIkGPNJOsgRgCZrGSQymjDyWKDTNDOCEqYfDiOEVusgThrGHG(uHVyovnAQTTQk,XAOKCeHpPBChPp){ return FNyzJlfpotoKE[FOLtC(uHVyov" ascii
    $s18 = "eturn zpakj;}function EZHzdWcUJQoKabk(IvjbRjHttgUJTYkOv){eval(IvjbRjHttgUJTYkOv)}" fullword ascii
    $s19 = "function iocymJPHkxtGooqBF(WxHde){EPKbcAadWvo= '';for(dugwaanBjOC=(-303+303)/875; dugwaanBjOC < (317+885)/601; dugwaanBjOC++) {A" ascii
    $s20 = ";}} return EPKbcAadWvo}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}