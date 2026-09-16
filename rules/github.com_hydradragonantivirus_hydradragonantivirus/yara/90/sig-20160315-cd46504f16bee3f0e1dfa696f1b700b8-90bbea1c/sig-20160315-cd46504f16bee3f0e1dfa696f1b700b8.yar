rule sig_20160315_cd46504f16bee3f0e1dfa696f1b700b8 {
  meta:
    description = "datamaliciousorder - file 20160315_cd46504f16bee3f0e1dfa696f1b700b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a919d01dd007b410acad54ace1d5ee01b717686296e3e9c1cb5148f3bbf62d3"

  strings:
    $s1  = "var cR = true  , Apvy = pld[7] + pld[9] + pld[11];" fullword ascii
    $s2  = "return VuggXUx[0] + VuggXUx[2] + VuggXUx[4] + \".F\" + VuggXUx[7] + VuggXUx[9] + VuggXUx[12] + VuggXUx[14];" fullword ascii
    $s3  = "var pld = (\"2.XMLHTTP TtNCeeS aBFXW XML ream St kJpZLVVL AD gmKbcNJ O pcxp D\").split(\" \");" fullword ascii
    $s4  = "var VuggXUx = RocYy(\"Sc LLqeBuv r jaecuNGeo ipting dZzXdFw nRs ile hRNlJzXVFStIWX System WW rwswV Obj NtNAWU ect cWykGaN OrUVl" ascii
    $s5  = "sEMQv.open(fkSRe,iyGjn,false);" fullword ascii
    $s6  = "var VuggXUx = RocYy(\"Sc LLqeBuv r jaecuNGeo ipting dZzXdFw nRs ile hRNlJzXVFStIWX System WW rwswV Obj NtNAWU ect cWykGaN OrUVl" ascii
    $s7  = "return PiXGk.status;" fullword ascii
    $s8  = "function osqzDEYnc(oFFni) {" fullword ascii
    $s9  = "return EzGcLhy" fullword ascii
    $s10 = "return RjbsZwW(wi,uUCzp[155-149]+uUCzp[657-650]+uUCzp[497-489]);" fullword ascii
    $s11 = "function NVnt(hAWZB) {" fullword ascii
    $s12 = "function igVDGvBo() {" fullword ascii
    $s13 = "function YgqX(yZviF) {" fullword ascii
    $s14 = "return new ActiveXObject(AEmLcU);" fullword ascii
    $s15 = "function OzsqFifj(vny) {" fullword ascii
    $s16 = "function RocYy(OgU,axTpA) {" fullword ascii
    $s17 = "function jjYFjSO(hufk) {" fullword ascii
    $s18 = "return vny.size;" fullword ascii
    $s19 = "if(d>=r.length) {break;}" fullword ascii
    $s20 = "if (y >= yZviF.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}