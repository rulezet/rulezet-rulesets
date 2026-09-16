rule TTP_XOR_MULT_DOSStub_5f46 {
  strings:
    $key_5f46 = { 0b 2e [2] 7f 36 [2] 38 34 [2] 7f 25 [2] 31 29 [2] 3d 23 [2] 2a 28 [2] 31 66 [2] 0c }

  condition:
    any of them
}