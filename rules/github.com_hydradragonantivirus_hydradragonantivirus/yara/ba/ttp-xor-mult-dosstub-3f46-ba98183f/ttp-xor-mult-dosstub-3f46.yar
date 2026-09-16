rule TTP_XOR_MULT_DOSStub_3f46 {
  strings:
    $key_3f46 = { 6b 2e [2] 1f 36 [2] 58 34 [2] 1f 25 [2] 51 29 [2] 5d 23 [2] 4a 28 [2] 51 66 [2] 6c }

  condition:
    any of them
}