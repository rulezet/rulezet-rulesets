rule TTP_XOR_MULT_DOSStub_0e27 {
  strings:
    $key_0e27 = { 5a 4f [2] 2e 57 [2] 69 55 [2] 2e 44 [2] 60 48 [2] 6c 42 [2] 7b 49 [2] 60 07 [2] 5d }

  condition:
    any of them
}