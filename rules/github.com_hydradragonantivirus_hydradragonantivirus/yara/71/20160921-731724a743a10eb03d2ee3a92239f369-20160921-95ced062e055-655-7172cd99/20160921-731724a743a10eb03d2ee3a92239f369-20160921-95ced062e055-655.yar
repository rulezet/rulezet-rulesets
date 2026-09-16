rule _20160921_731724a743a10eb03d2ee3a92239f369_20160921_95ced062e055_655 {
  meta:
    description = "datamaliciousorder - from files 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_95ced062e0552048d29cf59daab852db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash2       = "62e6b62d08a320533bdb97151951141555c4f9ccf26ad306c0e21644b883ab60"

  strings:
    $s1  = "on f000(){return \"MBb\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return " ascii
    $s2  = "return \"WIj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Wb\";})(" ascii
    $s3  = "{return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(" ascii
    $s4  = "unction f000(){return \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){ret" ascii
    $s5  = "ion f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return " ascii
    $s6  = ")(),(function f000(){return \"Oh\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s7  = ";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"XTn\";})(),(function f0" ascii
    $s8  = " f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"NB" ascii
    $s9  = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"MJq\";})" ascii
    $s10 = "tion f000(){return \"Oe\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return" ascii
    $s11 = "(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"MDb\";" ascii
    $s12 = "return \"YTp\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(" ascii
    $s13 = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return " ascii
    $s14 = "unction f000(){return \"Br\";})(),(function f000(){return \"Yx\";})(),(function f000(){return \"Wh\";})(),(function f000(){retur" ascii
    $s15 = "unction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){retu" ascii
    $s16 = "})(),(function f000(){return \"Km\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"DNa\";})(),(function f00" ascii
    $s17 = "f000(){return \"SEo\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MD" ascii
    $s18 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KDh\";})" ascii
    $s19 = "rn \"Vj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s20 = "Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"MDb\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}