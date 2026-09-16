rule TTP_XOR_MULT_DOSStub_7350 {
  strings:
    $key_7350 = { 27 38 [2] 53 20 [2] 14 22 [2] 53 33 [2] 1d 3f [2] 11 35 [2] 06 3e [2] 1d 70 [2] 20 }

  condition:
    any of them
}