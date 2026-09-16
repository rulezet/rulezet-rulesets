rule TTP_XOR_MULT_DOSStub_0757 {
  strings:
    $key_0757 = { 53 3f [2] 27 27 [2] 60 25 [2] 27 34 [2] 69 38 [2] 65 32 [2] 72 39 [2] 69 77 [2] 54 }

  condition:
    any of them
}