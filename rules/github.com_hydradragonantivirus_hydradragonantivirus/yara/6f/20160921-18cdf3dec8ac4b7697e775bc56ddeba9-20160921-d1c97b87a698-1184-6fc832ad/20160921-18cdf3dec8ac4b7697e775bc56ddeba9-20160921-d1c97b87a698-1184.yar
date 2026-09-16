rule _20160921_18cdf3dec8ac4b7697e775bc56ddeba9_20160921_d1c97b87a698_1184 {
  meta:
    description = "datamaliciousorder - from files 20160921_18cdf3dec8ac4b7697e775bc56ddeba9.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a1aa090c906360f52952b29d512b8c450c7e8c8cff28bc6fded6af15377b37c"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"

  strings:
    $s1  = ";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f00" ascii
    $s2  = "00(){return \"YTp\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg" ascii
    $s3  = "turn \"EZu\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s4  = "),(function f000(){return \"Sv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"Vj\";})(),(function f000(){r" ascii
    $s5  = "function f000(){return \"ZGq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(function f000(){re" ascii
    $s6  = "ction f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(function f000(){return" ascii
    $s7  = "return \"Sj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s8  = "ction f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return " ascii
    $s9  = "000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Lp" ascii
    $s10 = " f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"D" ascii
    $s11 = "000(){return \"DNa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn" ascii
    $s12 = "(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){r" ascii
    $s13 = "\"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(funct" ascii
    $s14 = "Xg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s15 = " \"WIj\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Iq\";})(),(func" ascii
    $s16 = "nction f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Uo\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}