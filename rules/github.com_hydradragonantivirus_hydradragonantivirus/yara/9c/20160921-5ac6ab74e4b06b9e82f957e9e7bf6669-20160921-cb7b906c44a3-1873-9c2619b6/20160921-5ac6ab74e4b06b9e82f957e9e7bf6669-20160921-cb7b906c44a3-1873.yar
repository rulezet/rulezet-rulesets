rule _20160921_5ac6ab74e4b06b9e82f957e9e7bf6669_20160921_cb7b906c44a3_1873 {
  meta:
    description = "datamaliciousorder - from files 20160921_5ac6ab74e4b06b9e82f957e9e7bf6669.js, 20160921_cb7b906c44a337d403a375918e9db0c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "50225d12c51a2decb97015971f8ce72487a24a69e64ec1d12fd7f720f2320cf3"
    hash2       = "2a06a7a374bfacf6c8c177295f8ab5c8e4e8db511406cc33fcef97866f72f9dc"

  strings:
    $s1  = "000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TRc" ascii
    $s2  = "on f000(){return \"Oh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"" ascii
    $s3  = "function f000(){return \"OUx\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"PTs\";})(),(function f000(){r" ascii
    $s4  = "0(){return \"Oh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\"" ascii
    $s5  = "Kl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"MBb\";})(),(functio" ascii
    $s6  = "rn \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s7  = "000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKl" ascii
    $s8  = "000(){return \"Vu\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn" ascii
    $s9  = "tion f000(){return \"Uo\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s10 = "000(){return \"Vu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"DIa\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}