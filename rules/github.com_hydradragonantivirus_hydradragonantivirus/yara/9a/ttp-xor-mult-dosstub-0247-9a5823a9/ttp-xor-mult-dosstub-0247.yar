rule TTP_XOR_MULT_DOSStub_0247 {
  strings:
    $key_0247 = { 56 2f [2] 22 37 [2] 65 35 [2] 22 24 [2] 6c 28 [2] 60 22 [2] 77 29 [2] 6c 67 [2] 51 }

  condition:
    any of them
}