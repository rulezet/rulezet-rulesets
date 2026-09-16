rule _20160921_17ed90b369ab37cb5f1e7dcf8f6bb253_20160921_daba59e7a6b9_1030 {
  meta:
    description = "datamaliciousorder - from files 20160921_17ed90b369ab37cb5f1e7dcf8f6bb253.js, 20160921_daba59e7a6b9ed6983cd2cbef1eb1597.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81de0ae14e0c288b697a0e3c7f3ced9b68b8377e75dff5322d654841e642a8a7"
    hash2       = "94c619539e853fdec1958270da7516c52bbcf442ee9ca0569d11e19e70ae29eb"

  strings:
    $s1  = "\"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Km\";})(),(funct" ascii
    $s2  = "00(){return \"DYs\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj" ascii
    $s3  = " f000(){return \"MDb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"K" ascii
    $s4  = "00(){return \"MDb\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"NBs" ascii
    $s5  = "f000(){return \"Lo\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZF" ascii
    $s6  = "\"MBb\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(funct" ascii
    $s7  = "(){return \"IAa\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s8  = "unction f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s9  = "ion f000(){return \"MDb\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return " ascii
    $s10 = "0(){return \"Km\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";}" ascii
    $s11 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"BMj\";})(),(function f000(){retu" ascii
    $s12 = " \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(func" ascii
    $s13 = "rn \"MBb\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MMz\";})(),(f" ascii
    $s14 = "return \"MDb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})()" ascii
    $s15 = "b\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s16 = "(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"YTp\"" ascii
    $s17 = "function f000(){return \"UEg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s18 = "b\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}