rule TTP_XOR_MULT_DOSStub_43af {
  strings:
    $key_43af = { 17 c7 [2] 63 df [2] 24 dd [2] 63 cc [2] 2d c0 [2] 21 ca [2] 36 c1 [2] 2d 8f [2] 10 }

  condition:
    any of them
}