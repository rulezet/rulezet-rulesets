rule _20160921_7ffe38e0972c323071684bfa98cafbdf_20160921_93e612a2f44e_1608 {
  meta:
    description = "datamaliciousorder - from files 20160921_7ffe38e0972c323071684bfa98cafbdf.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bc751383d4c72f88b3f59d9fde1f38f09a81b77ee4df0498bec1df7cd088bc7"
    hash2       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"

  strings:
    $s1  = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"DNa\";})(),(function " ascii
    $s2  = "n\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"KXg\";})(),(function" ascii
    $s3  = "(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";}" ascii
    $s4  = " \"QDg\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"SGs\";})(),(fu" ascii
    $s5  = "on f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"RLk\";})(),(function f000(){return " ascii
    $s6  = "tion f000(){return \"IAa\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s7  = "){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";}" ascii
    $s8  = "f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Z" ascii
    $s9  = "return \"Iq\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s10 = "ction f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){retur" ascii
    $s11 = ",(function f000(){return \"PTi\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BQb\";})(),(function f000()" ascii
    $s12 = "000(){return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"DI" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}