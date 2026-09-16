rule _20160921_694d4629e99fd1d23d60bc73e0e28e30_20160921_e354814fb086_5346 {
  meta:
    description = "datamaliciousorder - from files 20160921_694d4629e99fd1d23d60bc73e0e28e30.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01147c2f2f43df58f5a1b60481a04add7d73eba030abaeed3f9dedb1fd3574e4"
    hash2       = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"

  strings:
    $s1 = "ck(){return \"ADy\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo" ascii
    $s2 = "})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(" ascii
    $s3 = "\"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XHj\";})(),(fun" ascii
    $s4 = ",(function fuck(){return \"XFd\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){r" ascii
    $s5 = "nction fuck(){return \"Vf\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}