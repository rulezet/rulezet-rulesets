rule TTP_XOR_MULT_DOSStub_3846 {
  strings:
    $key_3846 = { 6c 2e [2] 18 36 [2] 5f 34 [2] 18 25 [2] 56 29 [2] 5a 23 [2] 4d 28 [2] 56 66 [2] 6b }

  condition:
    any of them
}