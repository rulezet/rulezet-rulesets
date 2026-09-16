rule TTP_XOR_MULT_DOSStub_3526 {
  strings:
    $key_3526 = { 61 4e [2] 15 56 [2] 52 54 [2] 15 45 [2] 5b 49 [2] 57 43 [2] 40 48 [2] 5b 06 [2] 66 }

  condition:
    any of them
}