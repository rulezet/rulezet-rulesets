rule sig_20160312_8c7e07c64eafc213e592b19fe47d274d {
  meta:
    description = "datamaliciousorder - file 20160312_8c7e07c64eafc213e592b19fe47d274d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4398a7dac57436913f57ee144e9f29a03b8b68758f4e1b6263a1837cc3a239b"

  strings:
    $s1  = "return iOysmZR[0] + iOysmZR[2] + iOysmZR[4] + \".F\" + iOysmZR[7] + iOysmZR[9] + iOysmZR[12] + iOysmZR[14];" fullword ascii
    $s2  = "var Fe = true  , WlnW = wYs[7] + wYs[9] + wYs[11];" fullword ascii
    $s3  = "var wYs = (\"2.XMLHTTP XDMcIJa xPnbO XML ream St kgWMeTDb AD eRGitcf O lbYY D\").split(\" \");" fullword ascii
    $s4  = "NHDOE.open(EGDVO,ZrSLr,false);" fullword ascii
    $s5  = "var iOysmZR = \"Sc PQzIfZZ r IgdpQikDz ipting dJhGFMI CHD ile VrTecIKfxWDWbQ System Wu qTZJX Obj uSXgcg ect atMinAV\".split(\" " ascii
    $s6  = "if(w>=f.length) {break;}" fullword ascii
    $s7  = "return mujpuFD(va,kREOL[665-659]+kREOL[298-291]+kREOL[820-812]);" fullword ascii
    $s8  = "uGY = w; break; " fullword ascii
    $s9  = "return new ActiveXObject(aymOvU);" fullword ascii
    $s10 = "if (jyeXe == 674-474){return true;} else {return false;}" fullword ascii
    $s11 = "function whjN(KgIIp) {" fullword ascii
    $s12 = "function snTpb(aymOvU) {" fullword ascii
    $s13 = "function nuiCjWyK(pAO) {" fullword ascii
    $s14 = "function iddu(Exhjb) {" fullword ascii
    $s15 = "return khez.responseBody;" fullword ascii
    $s16 = "return FoRQu.status;" fullword ascii
    $s17 = "function XojTZIrs() {" fullword ascii
    $s18 = "function nlBp(vRLUs) {" fullword ascii
    $s19 = "return XyBCums" fullword ascii
    $s20 = "function AOCKUOQD(zBpRC,PGAZZq) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}