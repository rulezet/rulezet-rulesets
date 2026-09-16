rule TTP_XOR_MULT_DOSStub_3050 {
  strings:
    $key_3050 = { 64 38 [2] 10 20 [2] 57 22 [2] 10 33 [2] 5e 3f [2] 52 35 [2] 45 3e [2] 5e 70 [2] 63 }

  condition:
    any of them
}