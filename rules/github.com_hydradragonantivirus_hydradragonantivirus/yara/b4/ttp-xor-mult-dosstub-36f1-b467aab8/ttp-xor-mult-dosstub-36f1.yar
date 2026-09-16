rule TTP_XOR_MULT_DOSStub_36f1 {
  strings:
    $key_36f1 = { 62 99 [2] 16 81 [2] 51 83 [2] 16 92 [2] 58 9e [2] 54 94 [2] 43 9f [2] 58 d1 [2] 65 }

  condition:
    any of them
}