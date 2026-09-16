rule TTP_XOR_MULT_DOSStub_5ff1 {
  strings:
    $key_5ff1 = { 0b 99 [2] 7f 81 [2] 38 83 [2] 7f 92 [2] 31 9e [2] 3d 94 [2] 2a 9f [2] 31 d1 [2] 0c }

  condition:
    any of them
}