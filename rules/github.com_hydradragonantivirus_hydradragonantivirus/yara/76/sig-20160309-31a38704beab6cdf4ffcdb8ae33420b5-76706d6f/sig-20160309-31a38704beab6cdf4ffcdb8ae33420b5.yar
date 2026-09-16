rule sig_20160309_31a38704beab6cdf4ffcdb8ae33420b5 {
  meta:
    description = "datamaliciousorder - file 20160309_31a38704beab6cdf4ffcdb8ae33420b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c7b826e401011ced1eb6566ee0aad125c889ac8d057a7cc81a9a0e5b63d617"

  strings:
    $s1  = "return iElkegc[0] + iElkegc[2] + iElkegc[4] + \".F\" + iElkegc[7] + iElkegc[9] + iElkegc[12] + iElkegc[14];" fullword ascii
    $s2  = "var Ym = true  , fHbl = dpQ[7] + dpQ[9] + dpQ[11];" fullword ascii
    $s3  = "xYfXZ.open(IEwDg,PbIHE,false);" fullword ascii
    $s4  = "var dpQ = (\"2.XMLHTTP gWAWzZA jdmXu XML ream St NZHawJNs AD cbNAnUW O BQQX D\").split(\" \");" fullword ascii
    $s5  = "var iElkegc = \"Sc iCYkIEm r IQREJoDVi ipting nVsFVYg zkm ile muIIMmSVNLqwFt System kQ PySTP Obj mxpvkP ect VXBCFKl\".split(\" " ascii
    $s6  = "if (BoGYP == 325-125){return true;} else {return false;}" fullword ascii
    $s7  = "function CmPS(xYfXZ,PbIHE,IEwDg) {" fullword ascii
    $s8  = "function xcht(SLiIw) {" fullword ascii
    $s9  = "function HpcL(vlqEt) {" fullword ascii
    $s10 = "function ljau(Dhpcb,sbrhU) {" fullword ascii
    $s11 = "if (kvaKd > 180724-476){return true;} else {return false;}" fullword ascii
    $s12 = "function XziL(APESw) {" fullword ascii
    $s13 = "return new ActiveXObject(nHZozN);" fullword ascii
    $s14 = "HfO = C; break; " fullword ascii
    $s15 = "function RtUIMZKKW(DziwrlwLPfi) {" fullword ascii
    $s16 = "return piQH.ExpandEnvironmentStrings(AdZTt);" fullword ascii
    $s17 = "if(C>=R.length) {break;}" fullword ascii
    $s18 = "function GyqrSxe(Krpo) {" fullword ascii
    $s19 = "function mRHuF(nHZozN) {" fullword ascii
    $s20 = "function YPSUhGWR(Tuf) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}