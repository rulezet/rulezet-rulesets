rule sig_20160520_9728e0a4ec795c2ff315350a5db154b5 {
  meta:
    description = "datamaliciousorder - file 20160520_9728e0a4ec795c2ff315350a5db154b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d804a8c3d07b2b08ea4b71013a003d83e5a273729592fcaf200bc350511c79a"

  strings:
    $s1  = "function XZfxMMRP(pEDNy) {var zUfFVWaC=YRyOPLZYRpvgVScPc[2];for(var SmkGN=0;SmkGN<pEDNy;SmkGN++){WVKEE+=zUfFVWaC.charAt(Math.flo" ascii
    $s2  = "function XZfxMMRP(pEDNy) {var zUfFVWaC=YRyOPLZYRpvgVScPc[2];for(var SmkGN=0;SmkGN<pEDNy;SmkGN++){WVKEE+=zUfFVWaC.charAt(Math.flo" ascii
    $s3  = "function IlGcIE(baODWS){return baODWS.ExpandEnvironmentStrings(YRyOPLZYRpvgVScPc[10])}" fullword ascii
    $s4  = "function oJxLRPUTP(oitSxKqnj,AqJQavu,jkndHCVX){" fullword ascii
    $s5  = "function PhaUv(JGBkbxfg,OkWGc,dUJuQqOXGb){JGBkbxfg.open();JGBkbxfg.type = 1;JGBkbxfg.write(OkWGc);JGBkbxfg.position = 0;JGBkbxfg" ascii
    $s6  = "function LoqxT(VwIQHBAt,vmLTLH,zjBqDHqui){RGqKq=VwIQHBAt.split(zjBqDHqui);XRCieLy = YRyOPLZYRpvgVScPc[13];for(fbwZThCn=0;fbwZThC" ascii
    $s7  = "function Spmu(vBSmvl,kWqzApe){VzJj = YRyOPLZYRpvgVScPc[11].split(YRyOPLZYRpvgVScPc[12]);kWqzApe.open(VzJj[0]+VzJj[2]+VzJj[3], vB" ascii
    $s8  = "Smvl, false);kWqzApe.send();}" fullword ascii
    $s9  = "function LoqxT(VwIQHBAt,vmLTLH,zjBqDHqui){RGqKq=VwIQHBAt.split(zjBqDHqui);XRCieLy = YRyOPLZYRpvgVScPc[13];for(fbwZThCn=0;fbwZThC" ascii
    $s10 = "n<vmLTLH.length;fbwZThCn++) {XRCieLy+=RGqKq[vmLTLH[fbwZThCn]];}return XRCieLy.substring(3,XRCieLy.length);}" fullword ascii
    $s11 = "function zZWnn(baODWS){return new ActiveXObject(baODWS);}" fullword ascii
    $s12 = "try{oJxLRPUTP(HFcJP[UpAW], kgaUGoe() + YRyOPLZYRpvgVScPc[9], 1)}catch(e){}; " fullword ascii
    $s13 = "function Spmu(vBSmvl,kWqzApe){VzJj = YRyOPLZYRpvgVScPc[11].split(YRyOPLZYRpvgVScPc[12]);kWqzApe.open(VzJj[0]+VzJj[2]+VzJj[3], vB" ascii
    $s14 = "function PhaUv(JGBkbxfg,OkWGc,dUJuQqOXGb){JGBkbxfg.open();JGBkbxfg.type = 1;JGBkbxfg.write(OkWGc);JGBkbxfg.position = 0;JGBkbxfg" ascii
    $s15 = "function kgaUGoe() {var BFQt=100000;var PrESpC = 100;return Math.random()*(BFQt-PrESpC)+PrESpC;}" fullword ascii
    $s16 = "or(Math.random()*zUfFVWaC.length));}return WVKEE;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}