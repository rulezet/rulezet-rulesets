rule TTP_XOR_MULT_DOSStub_3127 {
  strings:
    $key_3127 = { 65 4f [2] 11 57 [2] 56 55 [2] 11 44 [2] 5f 48 [2] 53 42 [2] 44 49 [2] 5f 07 [2] 62 }

  condition:
    any of them
}