rule TTP_XOR_MULT_DOSStub_3ff1 {
  strings:
    $key_3ff1 = { 6b 99 [2] 1f 81 [2] 58 83 [2] 1f 92 [2] 51 9e [2] 5d 94 [2] 4a 9f [2] 51 d1 [2] 6c }

  condition:
    any of them
}