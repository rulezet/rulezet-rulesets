rule TTP_XOR_MULT_DOSStub_63f1 {
  strings:
    $key_63f1 = { 37 99 [2] 43 81 [2] 04 83 [2] 43 92 [2] 0d 9e [2] 01 94 [2] 16 9f [2] 0d d1 [2] 30 }

  condition:
    any of them
}