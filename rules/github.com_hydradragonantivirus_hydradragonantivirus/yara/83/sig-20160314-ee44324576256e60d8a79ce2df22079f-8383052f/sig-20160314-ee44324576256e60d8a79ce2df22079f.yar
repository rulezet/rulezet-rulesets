rule sig_20160314_ee44324576256e60d8a79ce2df22079f {
  meta:
    description = "datamaliciousorder - file 20160314_ee44324576256e60d8a79ce2df22079f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d54ee487c30d840ddf2ce326e798213253f883c6da2e38fca6921d1b9cc0e6c6"

  strings:
    $s1  = "var yy = true  , Suzm = FwF[7] + FwF[9] + FwF[11];" fullword ascii
    $s2  = "return kjciOnN[0] + kjciOnN[2] + kjciOnN[4] + \".F\" + kjciOnN[7] + kjciOnN[9] + kjciOnN[12] + kjciOnN[14];" fullword ascii
    $s3  = "var kjciOnN = \"Sc FekvXGH r criDZrquz ipting smeZNpG DfC ile rFjEIgnkrHiYHr System HD FOGTW Obj mOBghh ect nqlagGe ZNMVr\".spli" ascii
    $s4  = "dJULE.open(UrLzx,scsOt,false);" fullword ascii
    $s5  = "var kjciOnN = \"Sc FekvXGH r criDZrquz ipting smeZNpG DfC ile rFjEIgnkrHiYHr System HD FOGTW Obj mOBghh ect nqlagGe ZNMVr\".spli" ascii
    $s6  = "var FwF = (\"2.XMLHTTP OeOgEZV PMdel XML ream St tsrhhthV AD vOIOwYU O MUvo D\").split(\" \");" fullword ascii
    $s7  = "function nHoY(EuOQJ,UfHQe) {" fullword ascii
    $s8  = "function ckoY(PiDsD,ZTtoj) {" fullword ascii
    $s9  = "function evsbf(yqpfWc) {" fullword ascii
    $s10 = "function FXTc(Bkvgh) {" fullword ascii
    $s11 = "return npMaUgt" fullword ascii
    $s12 = "function iIHM(bQTZG) {" fullword ascii
    $s13 = "return OEduu.status;" fullword ascii
    $s14 = "function Dyww(qdfaU) {" fullword ascii
    $s15 = "return new ActiveXObject(DQYnrH);" fullword ascii
    $s16 = "return xQFC.responseBody;" fullword ascii
    $s17 = "function JPlq(dJULE,scsOt,UrLzx) {" fullword ascii
    $s18 = "function vEhgkEg(xQFC) {" fullword ascii
    $s19 = "function DMgwlUvRD() {" fullword ascii
    $s20 = "function cQFY(ThasW) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}