rule TTP_XOR_MULT_DOSStub_1f46 {
  strings:
    $key_1f46 = { 4b 2e [2] 3f 36 [2] 78 34 [2] 3f 25 [2] 71 29 [2] 7d 23 [2] 6a 28 [2] 71 66 [2] 4c }

  condition:
    any of them
}