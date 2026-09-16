rule TTP_XOR_MULT_DOSStub_3750 {
  strings:
    $key_3750 = { 63 38 [2] 17 20 [2] 50 22 [2] 17 33 [2] 59 3f [2] 55 35 [2] 42 3e [2] 59 70 [2] 64 }

  condition:
    any of them
}