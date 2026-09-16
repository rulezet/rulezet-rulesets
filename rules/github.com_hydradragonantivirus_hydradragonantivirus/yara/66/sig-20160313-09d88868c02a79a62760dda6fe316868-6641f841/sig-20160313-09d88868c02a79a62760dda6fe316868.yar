rule sig_20160313_09d88868c02a79a62760dda6fe316868 {
  meta:
    description = "datamaliciousorder - file 20160313_09d88868c02a79a62760dda6fe316868.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1fb3fe1cfcdd96911e297dd46c280cc18ecb63edf8b7a550fc0feac2f315b62"

  strings:
    $s1  = "return vAIxbTR[0] + vAIxbTR[2] + vAIxbTR[4] + \".F\" + vAIxbTR[7] + vAIxbTR[9] + vAIxbTR[12] + vAIxbTR[14];" fullword ascii
    $s2  = "var XM = true  , OPQA = BxE[7] + BxE[9] + BxE[11];" fullword ascii
    $s3  = "var BxE = (\"2.XMLHTTP yBENsuY nBgoa XML ream St cwrkxSEJ AD twAibcr O vJDb D\").split(\" \");" fullword ascii
    $s4  = "var vAIxbTR = \"Sc lvAOaCw r bcOgcYWNF ipting kzThWzl Dcg ile PoiIJOQVRhgzNQ System Yr GxVko Obj VRByYU ect pNsloxu\".split(\" " ascii
    $s5  = "TqWTu.open(FFsty,UbUJb,false);" fullword ascii
    $s6  = "function CMXXS(AtJzfM) {" fullword ascii
    $s7  = "if(Y>=a.length) {break;}" fullword ascii
    $s8  = "function rcDV(jePVB) {" fullword ascii
    $s9  = "function gAgGYih(nFek,JJVlU) {" fullword ascii
    $s10 = "function uxCf(uTikA) {" fullword ascii
    $s11 = "function NxTm(fUeSU) {" fullword ascii
    $s12 = "function yWyY(TqWTu,UbUJb,FFsty) {" fullword ascii
    $s13 = "return TmD.size;" fullword ascii
    $s14 = "function nNJv(SSJQN,gbKZt) {" fullword ascii
    $s15 = "return HKFF.responseBody;" fullword ascii
    $s16 = "return new ActiveXObject(AtJzfM);" fullword ascii
    $s17 = "rIC = Y; break; " fullword ascii
    $s18 = "function EDxU(cLmGk) {" fullword ascii
    $s19 = "function oacHdHIMd() {" fullword ascii
    $s20 = "function ugxUUUIg(TmD) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}