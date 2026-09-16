rule sig_20160307_ab48bc210502e25c3c77685c0c4e149d {
  meta:
    description = "datamaliciousorder - file 20160307_ab48bc210502e25c3c77685c0c4e149d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1ef3b5afb390b050924c68528588c69e7e2afbf8d8f8a07cdfed4934826c4bd"

  strings:
    $s1  = "return waRghqj[0] + waRghqj[2] + waRghqj[4] + \".F\" + waRghqj[7] + waRghqj[9] + waRghqj[12] + waRghqj[14];" fullword ascii
    $s2  = "var me = true  , VNwV = Snm[7] + Snm[9] + Snm[11];" fullword ascii
    $s3  = "gIpFS.open(iSdPX,BSTxo,false);" fullword ascii
    $s4  = "var Snm = (\"2.XMLHTTP RMCnyYR xEDYc XML ream St wufUaUVs AD pJvuqAO O IFGM D\").split(\" \");" fullword ascii
    $s5  = "var waRghqj = \"Sc iekmswa r pHxIrAAbe ipting YqiENEL fnr ile JOatJclfjiPqJJ System yg uwBOH Obj PFyeLq ect FstTbcR\".split(\" " ascii
    $s6  = "if (hwVoM == 308-108){return true;} else {return false;}" fullword ascii
    $s7  = "function LILE(hwVoM) {" fullword ascii
    $s8  = "return ZpG.size;" fullword ascii
    $s9  = "function CmXU(TTwkz) {" fullword ascii
    $s10 = "function TrNP(jEjVC) {" fullword ascii
    $s11 = "return hhqgT.replace(new RegExp('!','g'), 'e');" fullword ascii
    $s12 = "return SYRchXM" fullword ascii
    $s13 = "function EjytKNKwv(aCHJP,NrLoX,GzXQR,ILFo) {" fullword ascii
    $s14 = "return SG.ExpandEnvironmentStrings(qtwzv[6]+qtwzv[7]+qtwzv[8]);" fullword ascii
    $s15 = "function hkXdPMl(iDMc) {" fullword ascii
    $s16 = "if (((new Date())>0,7248742888)) {" fullword ascii
    $s17 = "function HVIpLZzM(ZpG) {" fullword ascii
    $s18 = "if (maqNA > 169301-502){return true;} else {return false;}" fullword ascii
    $s19 = "if (j >= ffGsl.length) {break;}" fullword ascii
    $s20 = "function MRZx(gIpFS,BSTxo,iSdPX) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}