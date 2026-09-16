rule TTP_XOR_MULT_DOSStub_0727 {
  strings:
    $key_0727 = { 53 4f [2] 27 57 [2] 60 55 [2] 27 44 [2] 69 48 [2] 65 42 [2] 72 49 [2] 69 07 [2] 54 }

  condition:
    any of them
}