rule TTP_XOR_MULT_DOSStub_0e11 {
  strings:
    $key_0e11 = { 5a 79 [2] 2e 61 [2] 69 63 [2] 2e 72 [2] 60 7e [2] 6c 74 [2] 7b 7f [2] 60 31 [2] 5d }

  condition:
    any of them
}