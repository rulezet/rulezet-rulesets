rule TTP_XOR_MULT_DOSStub_4250 {
  strings:
    $key_4250 = { 16 38 [2] 62 20 [2] 25 22 [2] 62 33 [2] 2c 3f [2] 20 35 [2] 37 3e [2] 2c 70 [2] 11 }

  condition:
    any of them
}