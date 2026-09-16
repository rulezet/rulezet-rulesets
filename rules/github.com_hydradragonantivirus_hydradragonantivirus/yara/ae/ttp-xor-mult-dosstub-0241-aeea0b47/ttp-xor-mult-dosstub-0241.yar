rule TTP_XOR_MULT_DOSStub_0241 {
  strings:
    $key_0241 = { 56 29 [2] 22 31 [2] 65 33 [2] 22 22 [2] 6c 2e [2] 60 24 [2] 77 2f [2] 6c 61 [2] 51 }

  condition:
    any of them
}