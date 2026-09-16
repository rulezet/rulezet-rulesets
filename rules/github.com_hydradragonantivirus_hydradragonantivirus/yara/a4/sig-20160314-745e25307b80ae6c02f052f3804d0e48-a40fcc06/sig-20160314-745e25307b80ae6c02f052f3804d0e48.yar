rule sig_20160314_745e25307b80ae6c02f052f3804d0e48 {
  meta:
    description = "datamaliciousorder - file 20160314_745e25307b80ae6c02f052f3804d0e48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7eb667dc418beef9a7b84aa94e04c350971de92cde8217140b5d473d6f80f3f"

  strings:
    $s1  = "function mkpqdLlbq(YVOyZXacNlY) {" fullword ascii
    $s2  = "var oE = true  , IDGw = SXf[7] + SXf[9] + SXf[11];" fullword ascii
    $s3  = "return SqRLSsV[0] + SqRLSsV[2] + SqRLSsV[4] + \".F\" + SqRLSsV[7] + SqRLSsV[9] + SqRLSsV[12] + SqRLSsV[14];" fullword ascii
    $s4  = "var SqRLSsV = \"Sc PWAHQEY r zfFPqCHTz ipting DAfcBcj lOB ile xAnuTqZrMypGbN System IB eALPC Obj KLbWfj ect ZvFrzBK AmKuz\".spli" ascii
    $s5  = "var SqRLSsV = \"Sc PWAHQEY r zfFPqCHTz ipting DAfcBcj lOB ile xAnuTqZrMypGbN System IB eALPC Obj KLbWfj ect ZvFrzBK AmKuz\".spli" ascii
    $s6  = "HJpSH.open(TFMIO,kxwws,false);" fullword ascii
    $s7  = "var SXf = (\"2.XMLHTTP BGsBfhb iwZxm XML ream St mkITatcV AD IbSEfRo O pQhq D\").split(\" \");" fullword ascii
    $s8  = "function ekAnsyjHO() {" fullword ascii
    $s9  = "function iRhvaxLH() {" fullword ascii
    $s10 = "function ESMi(KlVNV) {" fullword ascii
    $s11 = "function fNoRKwX(MBtD) {" fullword ascii
    $s12 = "if(o>=h.length) {break;}" fullword ascii
    $s13 = "dncu(nkj); nkj.type = 1; xNBR(nkj,fNoRKwX(Ww)); if (haNk(uqnZyFVU(nkj)))  {" fullword ascii
    $s14 = "function dncu(sMHxc) {" fullword ascii
    $s15 = "return bXnVkhb(gk,smXer[577-571]+smXer[874-867]+smXer[695-687]);" fullword ascii
    $s16 = "return ALs.size;" fullword ascii
    $s17 = "function xQWBO(YIIzfP) {" fullword ascii
    $s18 = "if (S >= KlVNV.length) {break;}" fullword ascii
    $s19 = "return xRxy.ExpandEnvironmentStrings(ScUnz);" fullword ascii
    $s20 = "function KFIU(HJpSH,kxwws,TFMIO) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}