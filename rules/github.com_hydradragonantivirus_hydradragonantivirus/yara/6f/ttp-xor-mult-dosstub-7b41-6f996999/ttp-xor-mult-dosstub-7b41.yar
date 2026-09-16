rule TTP_XOR_MULT_DOSStub_7b41 {
  strings:
    $key_7b41 = { 2f 29 [2] 5b 31 [2] 1c 33 [2] 5b 22 [2] 15 2e [2] 19 24 [2] 0e 2f [2] 15 61 [2] 28 }

  condition:
    any of them
}