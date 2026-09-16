rule TTP_XOR_MULT_DOSStub_0b41 {
  strings:
    $key_0b41 = { 5f 29 [2] 2b 31 [2] 6c 33 [2] 2b 22 [2] 65 2e [2] 69 24 [2] 7e 2f [2] 65 61 [2] 58 }

  condition:
    any of them
}