rule TTP_XOR_MULT_DOSStub_11f1 {
  strings:
    $key_11f1 = { 45 99 [2] 31 81 [2] 76 83 [2] 31 92 [2] 7f 9e [2] 73 94 [2] 64 9f [2] 7f d1 [2] 42 }

  condition:
    any of them
}