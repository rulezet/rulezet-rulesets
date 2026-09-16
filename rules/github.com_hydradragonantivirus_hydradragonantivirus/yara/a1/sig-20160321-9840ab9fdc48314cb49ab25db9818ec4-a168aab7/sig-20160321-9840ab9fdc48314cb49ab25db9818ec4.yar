rule sig_20160321_9840ab9fdc48314cb49ab25db9818ec4 {
  meta:
    description = "datamaliciousorder - file 20160321_9840ab9fdc48314cb49ab25db9818ec4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b58429aabdb1c1937c33e179b5df80274f66cbfb14ba663d8fdd9eeb7504acbf"

  strings:
    $s1  = "return WScript.CreateObject(VmYhN);" fullword ascii
    $s2  = "return nYgniKq[0] + nYgniKq[2] + nYgniKq[4] + \".F\" + nYgniKq[7] + nYgniKq[9] + nYgniKq[12] + nYgniKq[14];" fullword ascii
    $s3  = "var Po = true  , PrZO = Fbk[7] + Fbk[9] + Fbk[11];" fullword ascii
    $s4  = "WXwuL.open(mMMoh,rtBqx,false);" fullword ascii
    $s5  = "var nYgniKq = dakmH(tkgXrncnyf+\" \"+\"System bi FyTDB Obj HseHlZ ect klVgCHe TWLkC\", \" \");" fullword ascii
    $s6  = "var Fbk = (\"2.XMLHTTP yEWxQvF yhjMZ XML ream St nxVTnEPt AD rKvNYOV O PPPs D\").split(\" \");" fullword ascii
    $s7  = "if (o >= MIiUA.length) {break;}" fullword ascii
    $s8  = "function YXgE(MIiUA) {" fullword ascii
    $s9  = "function rLImUuhS(brtD) {" fullword ascii
    $s10 = "return MNtBCj.position=476-476;" fullword ascii
    $s11 = "function FDEN(YiAaF,XDhpc) {" fullword ascii
    $s12 = "function DIDvo(MNtBCj) {" fullword ascii
    $s13 = "function VRyE(VfPIF,REGsX) {" fullword ascii
    $s14 = "function JlZMjHNMC(WWtwEhOtuus) {" fullword ascii
    $s15 = "return dLKmxdG(us,honqV[708-702]+honqV[595-588]+honqV[121-113]);" fullword ascii
    $s16 = "return new ActiveXObject(FdXqUu);" fullword ascii
    $s17 = "if(R>=W.length) {break;}" fullword ascii
    $s18 = "function MdgMxjjOn(nyfzT) {" fullword ascii
    $s19 = "ErZ = R; break; " fullword ascii
    $s20 = "function notJ(WXwuL,rtBqx,mMMoh) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}