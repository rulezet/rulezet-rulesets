rule TTP_XOR_MULT_DOSStub_4f66 {
  strings:
    $key_4f66 = { 1b 0e [2] 6f 16 [2] 28 14 [2] 6f 05 [2] 21 09 [2] 2d 03 [2] 3a 08 [2] 21 46 [2] 1c }

  condition:
    any of them
}