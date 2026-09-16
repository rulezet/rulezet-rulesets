rule TTP_XOR_MULT_DOSStub_0527 {
  strings:
    $key_0527 = { 51 4f [2] 25 57 [2] 62 55 [2] 25 44 [2] 6b 48 [2] 67 42 [2] 70 49 [2] 6b 07 [2] 56 }

  condition:
    any of them
}