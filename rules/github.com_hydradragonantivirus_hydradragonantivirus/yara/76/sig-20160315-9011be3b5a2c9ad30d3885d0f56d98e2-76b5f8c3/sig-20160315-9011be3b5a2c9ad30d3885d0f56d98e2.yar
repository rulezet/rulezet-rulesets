rule sig_20160315_9011be3b5a2c9ad30d3885d0f56d98e2 {
  meta:
    description = "datamaliciousorder - file 20160315_9011be3b5a2c9ad30d3885d0f56d98e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "532e60f042a7d279e9304a89ffa764fbcdd84fd56a9b5b7a9a23be23e332fbc4"

  strings:
    $s1  = "var Nx = true  , BwmK = jIf[7] + jIf[9] + jIf[11];" fullword ascii
    $s2  = "return OGympKl[0] + OGympKl[2] + OGympKl[4] + \".F\" + OGympKl[7] + OGympKl[9] + OGympKl[12] + OGympKl[14];" fullword ascii
    $s3  = "ueLBe.open(SWzbH,qCCKS,false);" fullword ascii
    $s4  = "var OGympKl = ztQeA(\"Sc iYlHqDo r FskiXFOAX ipting mKuxinV EcK ile pjrBhJzrWoRhvh System Qd jAcQb Obj uoAbCv ect iuUHYVG cYSpJ" ascii
    $s5  = "var OGympKl = ztQeA(\"Sc iYlHqDo r FskiXFOAX ipting mKuxinV EcK ile pjrBhJzrWoRhvh System Qd jAcQb Obj uoAbCv ect iuUHYVG cYSpJ" ascii
    $s6  = "return LjROP;" fullword ascii
    $s7  = "return Noj.split(JpBQY);" fullword ascii
    $s8  = "if (aVkOe > 198316-821){return true;} else {return false;}" fullword ascii
    $s9  = "return EebvBb.position=631-631;" fullword ascii
    $s10 = "function QBNc(SZGgx) {" fullword ascii
    $s11 = "function NipVjdG(PQmV,Kvbye) {" fullword ascii
    $s12 = "function SrHoR(EebvBb) {" fullword ascii
    $s13 = "function IWzjn(rnuVhL) {" fullword ascii
    $s14 = "function gKYJ(aVkOe) {" fullword ascii
    $s15 = "function nPUc(ueLBe,qCCKS,SWzbH) {" fullword ascii
    $s16 = "function bbzM(IHEmI,lGbbY) {" fullword ascii
    $s17 = "return qgt.size;" fullword ascii
    $s18 = "function YCzoUYFP(qgt) {" fullword ascii
    $s19 = "if (h >= JLCEp.length) {break;}" fullword ascii
    $s20 = "return oTKrVBM" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}