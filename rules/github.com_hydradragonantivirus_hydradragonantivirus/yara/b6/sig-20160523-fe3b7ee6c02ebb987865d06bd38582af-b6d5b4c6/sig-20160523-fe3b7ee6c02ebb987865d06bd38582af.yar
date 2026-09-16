rule sig_20160523_fe3b7ee6c02ebb987865d06bd38582af {
  meta:
    description = "datamaliciousorder - file 20160523_fe3b7ee6c02ebb987865d06bd38582af.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05ea27949636d784184ad12288f58e05a6886572002ca03c7362ecefe05c41cb"

  strings:
    $s1  = "function HZMCkEqvaN(GbsKHvWh,RDnkWNoDkFZW) {GbsKHvWh.Run(RDnkWNoDkFZW, 0x1, 0x0);}" fullword ascii
    $s2  = "function zbZqvZUbvx() {return/*BomLGRPywdGgpxaPhagUMYhhIGxASnCBHJZzlvzpwdBfKTbLmdlSiYQjCwBvwxpcyXotpkLhwOYBJZFSQngKQDdQQwOtMyrpu" ascii
    $s3  = "function gaBxzKEv(CzKDl) {var GMLhdwAG=TKVBGValUsX[13];for(var eZzEs=0;eZzEs<CzKDl;eZzEs++){LKUgL+=GMLhdwAG.charAt(Math.floor(Ma" ascii
    $s4  = "function gaBxzKEv(CzKDl) {var GMLhdwAG=TKVBGValUsX[13];for(var eZzEs=0;eZzEs<CzKDl;eZzEs++){LKUgL+=GMLhdwAG.charAt(Math.floor(Ma" ascii
    $s5  = "function vZvdy(TeXapw){return new ActiveXObject(TeXapw);}" fullword ascii
    $s6  = "function bznFNx(TeXapw){return TeXapw.ExpandEnvironmentStrings(TKVBGValUsX[9])}" fullword ascii
    $s7  = "function qokr(GXoroOZ,UcQHSpQ) {GXoroOZ.saveToFile(UcQHSpQ, 2);}" fullword ascii
    $s8  = "function nvqcK(wDhvuWfk,xyszzD,xYVszyrOv){SkaIq=wDhvuWfk.split(xYVszyrOv);DucHGnH = TKVBGValUsX[12];for(fhqIzlFR=0;fhqIzlFR<xysz" ascii
    $s9  = "th.random()*GMLhdwAG.length));}return LKUgL;}" fullword ascii
    $s10 = "function elkjLrn(hgYub) {hgYub.close();}" fullword ascii
    $s11 = "function zbZqvZUbvx() {return/*BomLGRPywdGgpxaPhagUMYhhIGxASnCBHJZzlvzpwdBfKTbLmdlSiYQjCwBvwxpcyXotpkLhwOYBJZFSQngKQDdQQwOtMyrpu" ascii
    $s12 = "function nvqcK(wDhvuWfk,xyszzD,xYVszyrOv){SkaIq=wDhvuWfk.split(xYVszyrOv);DucHGnH = TKVBGValUsX[12];for(fhqIzlFR=0;fhqIzlFR<xysz" ascii
    $s13 = "function MhuiToY() {var tPKZ=100000;var kxlfaa = 100;return vtNcKUf()*(tPKZ-kxlfaa)+kxlfaa;}" fullword ascii
    $s14 = "zD.length;fhqIzlFR++) {DucHGnH+=SkaIq[xyszzD[fhqIzlFR]];}return DucHGnH.substring(3,DucHGnH.length);}" fullword ascii
    $s15 = "function YPgN(LQiShY,JGVWayj){YemX = TKVBGValUsX[10].split(TKVBGValUsX[11]);JGVWayj.open(YemX[0]+YemX[2]+YemX[3], LQiShY, false)" ascii
    $s16 = "function qyAkvpQk(didxzTyib) {didxzTyib.type=1;}" fullword ascii
    $s17 = "function XEHP(uLXDot) {uLXDot.open();}" fullword ascii
    $s18 = "if(oMWy>IxqHL.length) break;" fullword ascii
    $s19 = "function vtNcKUf(){return Math.random();}" fullword ascii
    $s20 = "function VAAVRcQ(ITCK,gvOzQ) {ITCK.write(gvOzQ);}" fullword ascii

  condition:
    uint16(0) == 0x1227 and
    8 of them
}