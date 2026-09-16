rule TTP_XOR_MULT_DOSStub_2550 {
  strings:
    $key_2550 = { 71 38 [2] 05 20 [2] 42 22 [2] 05 33 [2] 4b 3f [2] 47 35 [2] 50 3e [2] 4b 70 [2] 76 }

  condition:
    any of them
}