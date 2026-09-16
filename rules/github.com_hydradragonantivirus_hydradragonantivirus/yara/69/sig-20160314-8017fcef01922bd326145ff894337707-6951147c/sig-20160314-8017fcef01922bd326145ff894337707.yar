rule sig_20160314_8017fcef01922bd326145ff894337707 {
  meta:
    description = "datamaliciousorder - file 20160314_8017fcef01922bd326145ff894337707.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "196e0ae2b3fd4fae297e4e2e61664b22a573f24168cdb9ee30ce5a3c99602b55"

  strings:
    $s1  = "var dX = true  , CcWT = Bsd[7] + Bsd[9] + Bsd[11];" fullword ascii
    $s2  = "return SGXjfhi[0] + SGXjfhi[2] + SGXjfhi[4] + \".F\" + SGXjfhi[7] + SGXjfhi[9] + SGXjfhi[12] + SGXjfhi[14];" fullword ascii
    $s3  = "var SGXjfhi = \"Sc iJlVAyz r QeGlDrzPq ipting qBtMrFy jTt ile ElzsFwvRLLYkTh System Ig jQwPy Obj utTpcS ect wMudhld cFzMn\".spli" ascii
    $s4  = "iazQK.open(xuUkQ,Mxmfx,false);" fullword ascii
    $s5  = "var Bsd = (\"2.XMLHTTP ACylPRh vpydy XML ream St BFbNXKKR AD PglRlSW O EeiN D\").split(\" \");" fullword ascii
    $s6  = "var SGXjfhi = \"Sc iJlVAyz r QeGlDrzPq ipting qBtMrFy jTt ile ElzsFwvRLLYkTh System Ig jQwPy Obj utTpcS ect wMudhld cFzMn\".spli" ascii
    $s7  = "function aAqlbdZc() {" fullword ascii
    $s8  = "function MUvQ(Frhjx,IYTmH) {" fullword ascii
    $s9  = "return MroQQT.position=784-784;" fullword ascii
    $s10 = "if (O >= GNyqf.length) {break;}" fullword ascii
    $s11 = "function sdmfe(MroQQT) {" fullword ascii
    $s12 = "function yCPWEfJ(aROJ) {" fullword ascii
    $s13 = "return QDAGuqA" fullword ascii
    $s14 = "function uObZ(wYLrS) {" fullword ascii
    $s15 = "function leRcMWyzh() {" fullword ascii
    $s16 = "if(T>=H.length) {break;}" fullword ascii
    $s17 = "return CeDuY;" fullword ascii
    $s18 = "function ULrD(lXZyN,GGhRc) {" fullword ascii
    $s19 = "return anC.size;" fullword ascii
    $s20 = "function qFQR(xXTSU) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}