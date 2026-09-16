rule TTP_XOR_MULT_DOSStub_1156 {
  strings:
    $key_1156 = { 45 3e [2] 31 26 [2] 76 24 [2] 31 35 [2] 7f 39 [2] 73 33 [2] 64 38 [2] 7f 76 [2] 42 }

  condition:
    any of them
}