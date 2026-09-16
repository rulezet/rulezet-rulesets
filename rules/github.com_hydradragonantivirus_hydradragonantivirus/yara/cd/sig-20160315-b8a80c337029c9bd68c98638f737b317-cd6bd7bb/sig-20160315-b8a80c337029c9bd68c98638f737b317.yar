rule sig_20160315_b8a80c337029c9bd68c98638f737b317 {
  meta:
    description = "datamaliciousorder - file 20160315_b8a80c337029c9bd68c98638f737b317.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0759a55cf93bcc335fd2ecb3b3c3c03474f3eed1e789d32b1c55d4fdcb1c59a"

  strings:
    $s1  = "var Vp = true  , wbpX = dEy[7] + dEy[9] + dEy[11];" fullword ascii
    $s2  = "return GpXMgmh[0] + GpXMgmh[2] + GpXMgmh[4] + \".F\" + GpXMgmh[7] + GpXMgmh[9] + GpXMgmh[12] + GpXMgmh[14];" fullword ascii
    $s3  = "HrwkN.open(jGiBW,XUDAI,false);" fullword ascii
    $s4  = "var GpXMgmh = yenrU(\"Sc lnOnvEK r raPVcmvjI ipting BHOlbHX qxA ile cDBMmUBchzkpsJ System Ml kzSRK Obj dKqchK ect bKkfDnP lHgHm" ascii
    $s5  = "var dEy = (\"2.XMLHTTP HMtGjFD LrtXH XML ream St bDtYWHJN AD qQBYVuf O WWdS D\").split(\" \");" fullword ascii
    $s6  = "var GpXMgmh = yenrU(\"Sc lnOnvEK r raPVcmvjI ipting BHOlbHX qxA ile cDBMmUBchzkpsJ System Ml kzSRK Obj dKqchK ect bKkfDnP lHgHm" ascii
    $s7  = "if(c>=F.length) {break;}" fullword ascii
    $s8  = "function hgqup(qpmWfe) {" fullword ascii
    $s9  = "return lTOX.responseBody;" fullword ascii
    $s10 = "function yenrU(yPf,xsQCN) {" fullword ascii
    $s11 = "function crcG(YjLBB) {" fullword ascii
    $s12 = "return jWRxDRh" fullword ascii
    $s13 = "if (TBmvE == 347-147){return true;} else {return false;}" fullword ascii
    $s14 = "return yPf.split(xsQCN);" fullword ascii
    $s15 = "function EXUp(HrwkN,XUDAI,jGiBW) {" fullword ascii
    $s16 = "function dEEKfLBc() {" fullword ascii
    $s17 = "function hdlYEytX(Trk) {" fullword ascii
    $s18 = "if (joHqh > 165753-470){return true;} else {return false;}" fullword ascii
    $s19 = "function zAgRV(XGXiFN) {" fullword ascii
    $s20 = "function qIZO(TBmvE) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}