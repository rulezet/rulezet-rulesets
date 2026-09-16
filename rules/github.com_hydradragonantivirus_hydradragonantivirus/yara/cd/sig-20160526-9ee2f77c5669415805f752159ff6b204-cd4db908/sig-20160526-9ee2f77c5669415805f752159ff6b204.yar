rule sig_20160526_9ee2f77c5669415805f752159ff6b204 {
  meta:
    description = "datamaliciousorder - file 20160526_9ee2f77c5669415805f752159ff6b204.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b02a8353e868d822f13df4dc9ee09253b91a834ee59ff5d708fa4e72c01d1a1"

  strings:
    $s1  = "function pPfEiseoNga(jVAkHZplSFLuN) {var OzKjCBqECNOjwfyNAgIl = pvZufCwx.join(OLMonzMIV[0]);var ZPRHcKkrWFOuhhAWHaBcii, yXcPbWOy" ascii
    $s2  = "+ Math.pow(Math.cos(687), 2) - 1))-105)) wilBmOcMmfW += Yy(ZPRHcKkrWFOuhhAWHaBcii);else if (rEYWUCKSBcDStnOiIuTCik == (952 + Mat" ascii
    $s3  = "function gypMArTKmNPgV(fazNqdDSkxUreW,ONGMWoOTNwqgSPSfDtcxjIPL){return fazNqdDSkxUreW.charAt(ONGMWoOTNwqgSPSfDtcxjIPL);}" fullword ascii
    $s4  = "function Yy(HZxldO){return String.fromCharCode(HZxldO);}" fullword ascii
    $s5  = "function pPfEiseoNga(jVAkHZplSFLuN) {var OzKjCBqECNOjwfyNAgIl = pvZufCwx.join(OLMonzMIV[0]);var ZPRHcKkrWFOuhhAWHaBcii, yXcPbWOy" ascii
    $s6  = "function DRqwQo(HynaUsZGZyXWSJrEHoaC,oeUzuaRdZWji,bBxEVEB){return String.fromCharCode(HynaUsZGZyXWSJrEHoaC,oeUzuaRdZWji,bBxEVEB)" ascii
    $s7  = "function CPEUHFkxTwSB(GKBGADnV,YFqaoIwHKPk){return GKBGADnV.indexOf(YFqaoIwHKPk);}" fullword ascii
    $s8  = ";} while (ECFfPDvZPurIwAPFqejqV < jVAkHZplSFLuN.length);return wilBmOcMmfW;}" fullword ascii
    $s9  = "function WHBSqszxBzmuR(rdPpBTsCtyykvQTAQAoMDYfE,lPkxPqHHYdlxRmmJYZbImq){return String.fromCharCode(rdPpBTsCtyykvQTAQAoMDYfE,lPkx" ascii
    $s10 = ", yXcPbWOyMwLmBApSOESeZXvm);else wilBmOcMmfW += DRqwQo(ZPRHcKkrWFOuhhAWHaBcii, yXcPbWOyMwLmBApSOESeZXvm, vnVnOISoamKwxkhkAQbVMK)" ascii
    $s11 = "function WHBSqszxBzmuR(rdPpBTsCtyykvQTAQAoMDYfE,lPkxPqHHYdlxRmmJYZbImq){return String.fromCharCode(rdPpBTsCtyykvQTAQAoMDYfE,lPkx" ascii
    $s12 = "function DRqwQo(HynaUsZGZyXWSJrEHoaC,oeUzuaRdZWji,bBxEVEB){return String.fromCharCode(HynaUsZGZyXWSJrEHoaC,oeUzuaRdZWji,bBxEVEB)" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}