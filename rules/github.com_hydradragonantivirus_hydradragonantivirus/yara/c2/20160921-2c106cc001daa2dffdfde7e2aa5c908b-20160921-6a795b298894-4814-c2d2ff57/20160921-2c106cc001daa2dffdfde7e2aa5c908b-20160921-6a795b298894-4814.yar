rule _20160921_2c106cc001daa2dffdfde7e2aa5c908b_20160921_6a795b298894_4814 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c106cc001daa2dffdfde7e2aa5c908b.js, 20160921_6a795b29889480550a8440815b06fa7d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca5356b92abf859d45d843749f45e5e06c7d045b4e7ea5d215ab87cdb8c8f66b"
    hash2       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"

  strings:
    $s1 = "n \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Yk\";})(),(fun" ascii
    $s2 = "ck(){return \"DAa\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ik" ascii
    $s3 = "function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){re" ascii
    $s4 = " \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Wo0\";})(),(fu" ascii
    $s5 = " \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}