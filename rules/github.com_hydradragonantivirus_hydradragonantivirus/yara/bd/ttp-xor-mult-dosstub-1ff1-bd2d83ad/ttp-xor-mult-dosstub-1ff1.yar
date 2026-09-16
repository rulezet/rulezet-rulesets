rule TTP_XOR_MULT_DOSStub_1ff1 {
  strings:
    $key_1ff1 = { 4b 99 [2] 3f 81 [2] 78 83 [2] 3f 92 [2] 71 9e [2] 7d 94 [2] 6a 9f [2] 71 d1 [2] 4c }

  condition:
    any of them
}