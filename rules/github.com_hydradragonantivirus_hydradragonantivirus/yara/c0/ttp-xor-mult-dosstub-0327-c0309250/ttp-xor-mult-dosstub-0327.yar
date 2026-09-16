rule TTP_XOR_MULT_DOSStub_0327 {
  strings:
    $key_0327 = { 57 4f [2] 23 57 [2] 64 55 [2] 23 44 [2] 6d 48 [2] 61 42 [2] 76 49 [2] 6d 07 [2] 50 }

  condition:
    any of them
}