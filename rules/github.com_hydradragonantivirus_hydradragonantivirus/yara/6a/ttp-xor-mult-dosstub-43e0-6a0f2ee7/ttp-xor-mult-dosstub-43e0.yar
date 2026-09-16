rule TTP_XOR_MULT_DOSStub_43e0 {
  strings:
    $key_43e0 = { 17 88 [2] 63 90 [2] 24 92 [2] 63 83 [2] 2d 8f [2] 21 85 [2] 36 8e [2] 2d c0 [2] 10 }

  condition:
    any of them
}