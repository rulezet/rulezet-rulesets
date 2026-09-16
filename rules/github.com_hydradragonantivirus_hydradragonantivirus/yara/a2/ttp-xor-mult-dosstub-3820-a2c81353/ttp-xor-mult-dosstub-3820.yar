rule TTP_XOR_MULT_DOSStub_3820 {
  strings:
    $key_3820 = { 6c 48 [2] 18 50 [2] 5f 52 [2] 18 43 [2] 56 4f [2] 5a 45 [2] 4d 4e [2] 56 00 [2] 6b }

  condition:
    any of them
}