rule _20160921_6ad2178e7d047e60c71f9fe1ca457b74_20160921_acebc8ac4559_119 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ad2178e7d047e60c71f9fe1ca457b74.js, 20160921_acebc8ac4559526a5a8de801968bd19f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e126f3a35c3e15739f44a3b15bf991678bc6c232e213be738a2521187bf8173"
    hash2       = "79fe55ec3d2d6dbd854df9676c4565b6a8410e1d94298c2ff2f112036fcfac73"

  strings:
    $s1  = "tion f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return" ascii
    $s2  = ";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f00" ascii
    $s3  = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"MMz\"" ascii
    $s4  = "(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){re" ascii
    $s5  = "n f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"" ascii
    $s6  = "tion f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s7  = "\"MMz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wh\";})(),(func" ascii
    $s8  = "ction f000(){return \"HJm\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"UEg\";})(),(function f000(){retur" ascii
    $s9  = "tion f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s10 = "Go\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZFe\";})(),(functio" ascii
    $s11 = " f000(){return \"Nv\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s12 = "})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000" ascii
    $s13 = "rn \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(f" ascii
    $s14 = "\"ZGq\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"NYh\";})(),(func" ascii
    $s15 = " f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"" ascii
    $s16 = "nction f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){retur" ascii
    $s17 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"YTp\";})(),(function f0" ascii
    $s18 = "){return \"SGs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";}" ascii
    $s19 = "unction f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"MMz\";})(),(function f000(){re" ascii
    $s20 = "00(){return \"ZFe\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}