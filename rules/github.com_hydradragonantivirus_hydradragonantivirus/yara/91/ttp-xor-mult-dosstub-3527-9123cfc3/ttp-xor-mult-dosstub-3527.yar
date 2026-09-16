rule TTP_XOR_MULT_DOSStub_3527 {
  strings:
    $key_3527 = { 61 4f [2] 15 57 [2] 52 55 [2] 15 44 [2] 5b 48 [2] 57 42 [2] 40 49 [2] 5b 07 [2] 66 }

  condition:
    any of them
}