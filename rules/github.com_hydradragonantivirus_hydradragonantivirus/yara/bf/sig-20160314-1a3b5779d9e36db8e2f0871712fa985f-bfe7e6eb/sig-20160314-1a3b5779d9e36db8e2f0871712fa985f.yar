rule sig_20160314_1a3b5779d9e36db8e2f0871712fa985f {
  meta:
    description = "datamaliciousorder - file 20160314_1a3b5779d9e36db8e2f0871712fa985f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "363cfd0513b30204f5a18b6012e12e7235b3ab8f42f3e6090e4cd73d56c76545"

  strings:
    $s1  = "return EgpaLPh[0] + EgpaLPh[2] + EgpaLPh[4] + \".F\" + EgpaLPh[7] + EgpaLPh[9] + EgpaLPh[12] + EgpaLPh[14];" fullword ascii
    $s2  = "var NH = true  , rWSH = qFz[7] + qFz[9] + qFz[11];" fullword ascii
    $s3  = "PYyYN.open(Ndvos,rZPUn,false);" fullword ascii
    $s4  = "var qFz = (\"2.XMLHTTP FMMyPVX Uyyhb XML ream St YberjACZ AD zBkwQmg O UzZZ D\").split(\" \");" fullword ascii
    $s5  = "var EgpaLPh = \"Sc TkeeNnm r chOuExhGW ipting eQtbgfB cHr ile JjXDAqkzNogIft System oO eMmaA Obj uJrtnn ect EXnwwZS mPCIg\".spli" ascii
    $s6  = "var EgpaLPh = \"Sc TkeeNnm r chOuExhGW ipting eQtbgfB cHr ile JjXDAqkzNogIft System oO eMmaA Obj uJrtnn ect EXnwwZS mPCIg\".spli" ascii
    $s7  = "function jQhp(qHCsm) {" fullword ascii
    $s8  = "function AyHE(UHxdY) {" fullword ascii
    $s9  = "function WKKQx(rcgIMQ) {" fullword ascii
    $s10 = "return dZXJEe.position=478-478;" fullword ascii
    $s11 = "function VEwg(LGkhf) {" fullword ascii
    $s12 = "function nmKRvHWa() {" fullword ascii
    $s13 = "return NJdLWBq" fullword ascii
    $s14 = "return HTC.size;" fullword ascii
    $s15 = "function BmpM(yhRbh) {" fullword ascii
    $s16 = "if (yhRbh > 163947-798){return true;} else {return false;}" fullword ascii
    $s17 = "if(h>=x.length) {break;}" fullword ascii
    $s18 = "return iuolhht(HG,luekr[290-284]+luekr[648-641]+luekr[160-152]);" fullword ascii
    $s19 = "return new ActiveXObject(rcgIMQ);" fullword ascii
    $s20 = "return HtUU.ExpandEnvironmentStrings(KXfDa);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}