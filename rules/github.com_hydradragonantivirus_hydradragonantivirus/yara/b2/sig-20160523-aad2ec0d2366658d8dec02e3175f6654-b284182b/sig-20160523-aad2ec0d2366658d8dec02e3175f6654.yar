rule sig_20160523_aad2ec0d2366658d8dec02e3175f6654 {
  meta:
    description = "datamaliciousorder - file 20160523_aad2ec0d2366658d8dec02e3175f6654.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f52e5e8840d8b06587f35ffb0c1fe5d3fbd381f4eebd7d3bbab3c77880d35649"

  strings:
    $s1  = "function wVwQYGBhlf() {return/*WYnFRYEMLUtsoVwpPAWPLjlKqnIFwfUFcdwoVrWjJboLVTzGAENHIBNliylqbmqhpitnXPOJMeOpartrunLuarQsDOZbOuiVo" ascii
    $s2  = "function fatBHgIpGD(EXAlZwsW,agawcEnGiPcz) {EXAlZwsW.Run(agawcEnGiPcz, 0x1, 0x0);}" fullword ascii
    $s3  = "function hSShHaSy(xNrUB) {var FtSaisah=MKIWEsGMzCesOhyVKjgzcu[13];for(var IgOfK=0;IgOfK<xNrUB;IgOfK++){oLGlQ+=FtSaisah.charAt(Ma" ascii
    $s4  = "function hSShHaSy(xNrUB) {var FtSaisah=MKIWEsGMzCesOhyVKjgzcu[13];for(var IgOfK=0;IgOfK<xNrUB;IgOfK++){oLGlQ+=FtSaisah.charAt(Ma" ascii
    $s5  = "function wVwQYGBhlf() {return/*WYnFRYEMLUtsoVwpPAWPLjlKqnIFwfUFcdwoVrWjJboLVTzGAENHIBNliylqbmqhpitnXPOJMeOpartrunLuarQsDOZbOuiVo" ascii
    $s6  = "function RdkHnKW(cnoGU) {cnoGU.close();}" fullword ascii
    $s7  = "function oTdXjH(GPPPPo){return GPPPPo.ExpandEnvironmentStrings(MKIWEsGMzCesOhyVKjgzcu[9])}" fullword ascii
    $s8  = "function CRWii(LeAXVCCi,XJGEr,HYbEJNXkif){Vxhl(LeAXVCCi);PFoMhClO(LeAXVCCi);DAOTXcS(LeAXVCCi,XJGEr);pdrYSZfPx(LeAXVCCi);DTTC(LeA" ascii
    $s9  = "function pdrYSZfPx(oSmfQB) {var uIkqPcdFoS=[];oSmfQB.position=uIkqPcdFoS.length*(1148540-828);}" fullword ascii
    $s10 = "function MgvI(OBrgHA,RPMkbiy){mBnK = MKIWEsGMzCesOhyVKjgzcu[10].split(MKIWEsGMzCesOhyVKjgzcu[11]);RPMkbiy.open(mBnK[0]+mBnK[2]+m" ascii
    $s11 = "function wUIVawO(){return Math.random();}" fullword ascii
    $s12 = "function MOBymND() {var gHOo=100000;var vwMqKf = 100;return wUIVawO()*(gHOo-vwMqKf)+vwMqKf;}" fullword ascii
    $s13 = "function WyAwZpgHdvyKe() {wVwQYGBhlf().Sleep(2359012-863);}" fullword ascii
    $s14 = "function kwYuq(INwMsRuw,thuCkN,eVrYbnaab){qVdTR=INwMsRuw.split(eVrYbnaab);xtaDSkF = MKIWEsGMzCesOhyVKjgzcu[12];for(dCpgVJFH=0;dC" ascii
    $s15 = "function MgvI(OBrgHA,RPMkbiy){mBnK = MKIWEsGMzCesOhyVKjgzcu[10].split(MKIWEsGMzCesOhyVKjgzcu[11]);RPMkbiy.open(mBnK[0]+mBnK[2]+m" ascii
    $s16 = "function CRWii(LeAXVCCi,XJGEr,HYbEJNXkif){Vxhl(LeAXVCCi);PFoMhClO(LeAXVCCi);DAOTXcS(LeAXVCCi,XJGEr);pdrYSZfPx(LeAXVCCi);DTTC(LeA" ascii
    $s17 = "th.floor(Math.random()*FtSaisah.length));}return oLGlQ;}" fullword ascii
    $s18 = "function kwYuq(INwMsRuw,thuCkN,eVrYbnaab){qVdTR=INwMsRuw.split(eVrYbnaab);xtaDSkF = MKIWEsGMzCesOhyVKjgzcu[12];for(dCpgVJFH=0;dC" ascii
    $s19 = "function DTTC(EPgIEtx,msntEHt) {EPgIEtx.saveToFile(msntEHt, 2);}" fullword ascii
    $s20 = "function UiIUt(GPPPPo){return new ActiveXObject(GPPPPo);}" fullword ascii

  condition:
    uint16(0) == 0x1827 and
    8 of them
}