rule _20160921_06311313c2c91f30b188be9b0f27e37d_20160921_13c992e435ed_827 {
  meta:
    description = "datamaliciousorder - from files 20160921_06311313c2c91f30b188be9b0f27e37d.js, 20160921_13c992e435ed245b1977cea0df2db815.js, 20160921_4a2d69f96df0dd4c57fda9e63c804950.js, 20160922_92c62e47426236a3598469915ee3dcfe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e8ad2d8de7bc2cc77c2b00b8eeb4fd7976cd68790eeb4b6bfd14ad188696ed0"
    hash2       = "289da9cff140ea3b4e35a1aa721314733c057d085ff9e8b5fc3ed7e10f75341b"
    hash3       = "786d4a5233f100c1ba7f5e820c46309247158a45ed43bd58795f05152dbaecf6"
    hash4       = "d6b6eb713cecae41143fb04e090a4809564a1837f49e53a84e27f0d3b0885df7"

  strings:
    $s1  = ",(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"MMz\";})(),(function f000()" ascii
    $s2  = "(),(function f000(){return \"Qa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"XTn\";})(),(function f000()" ascii
    $s3  = "nction f000(){return \"IAa\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Iq\";})(),(function f000(){retur" ascii
    $s4  = "unction f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Lp\";})(),(function f000(){ret" ascii
    $s5  = "\"BMj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(func" ascii
    $s6  = "(function f000(){return \"Ut\";})(),(function f000(){return \"Wh\";})(),(function f000(){return \"Zj\";})(),(function f000(){ret" ascii
    $s7  = "Yi\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function " ascii
    $s8  = "){return \"KDh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DIa\";" ascii
    $s9  = "000(){return \"Um\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj" ascii
    $s10 = "unction f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){ret" ascii
    $s11 = "n f000(){return \"MBb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"V" ascii
    $s12 = "0(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\"" ascii
    $s13 = "w\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"MJq\";})(),(functio" ascii
    $s14 = "00(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi" ascii
    $s15 = "),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MMz\";})(),(function f000()" ascii
    $s16 = "function f000(){return \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){r" ascii
    $s17 = "(){return \"MJq\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s18 = "f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg" ascii
    $s19 = "{return \"PTs\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})" ascii
    $s20 = "tion f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}