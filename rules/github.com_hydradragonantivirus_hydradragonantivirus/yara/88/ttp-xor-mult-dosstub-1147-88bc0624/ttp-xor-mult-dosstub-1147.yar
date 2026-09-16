rule TTP_XOR_MULT_DOSStub_1147 {
  strings:
    $key_1147 = { 45 2f [2] 31 37 [2] 76 35 [2] 31 24 [2] 7f 28 [2] 73 22 [2] 64 29 [2] 7f 67 [2] 42 }

  condition:
    any of them
}