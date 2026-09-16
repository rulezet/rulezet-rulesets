rule TTP_XOR_MULT_DOSStub_6050 {
  strings:
    $key_6050 = { 34 38 [2] 40 20 [2] 07 22 [2] 40 33 [2] 0e 3f [2] 02 35 [2] 15 3e [2] 0e 70 [2] 33 }

  condition:
    any of them
}