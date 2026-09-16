rule sig_20160309_f55f756d3e7523f638609cb3e79c08f6 {
  meta:
    description = "datamaliciousorder - file 20160309_f55f756d3e7523f638609cb3e79c08f6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6c2c2f880dea4fb4ac12a7fd8c575c7ffb4fd9e31663653bb4a950de57033b5f"

  strings:
    $s1  = "return RnjbxGv[0] + RnjbxGv[2] + RnjbxGv[4] + \".F\" + RnjbxGv[7] + RnjbxGv[9] + RnjbxGv[12] + RnjbxGv[14];" fullword ascii
    $s2  = "var Xy = true  , spIQ = aAL[7] + aAL[9] + aAL[11];" fullword ascii
    $s3  = "var aAL = (\"2.XMLHTTP jmRfDvI KkwAT XML ream St MkwoiyzF AD yHhOlsS O esWG D\").split(\" \");" fullword ascii
    $s4  = "TcRUX.open(yiYgK,kcFWH,false);" fullword ascii
    $s5  = "function ebPfLoI(jERG) {" fullword ascii
    $s6  = "function hrII(VtnUf) {" fullword ascii
    $s7  = "function umtp(jfunq) {" fullword ascii
    $s8  = "return REYR.ExpandEnvironmentStrings(kDyax);" fullword ascii
    $s9  = "function pICJz(hVfFKQ) {" fullword ascii
    $s10 = "function RkSlNRRSg(DpeTiBHyVlu) {" fullword ascii
    $s11 = "function TuuO(agOXg,JdsTG) {" fullword ascii
    $s12 = "return SqlKP.status;" fullword ascii
    $s13 = "function YxAm(HhuaM,nUkdl) {" fullword ascii
    $s14 = "return jyEzPYW(tV,Okhaj[403-397]+Okhaj[296-289]+Okhaj[439-431]);" fullword ascii
    $s15 = "return DQH.size;" fullword ascii
    $s16 = "return sKfubdu" fullword ascii
    $s17 = "if(G>=b.length) {break;}" fullword ascii
    $s18 = "function jIrwnsXo() {" fullword ascii
    $s19 = "return new ActiveXObject(hVfFKQ);" fullword ascii
    $s20 = "function LeseEwfz(DQH) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}