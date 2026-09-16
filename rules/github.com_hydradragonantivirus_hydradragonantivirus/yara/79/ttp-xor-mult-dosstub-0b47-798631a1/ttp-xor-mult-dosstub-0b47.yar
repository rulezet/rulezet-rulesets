rule TTP_XOR_MULT_DOSStub_0b47 {
  strings:
    $key_0b47 = { 5f 2f [2] 2b 37 [2] 6c 35 [2] 2b 24 [2] 65 28 [2] 69 22 [2] 7e 29 [2] 65 67 [2] 58 }

  condition:
    any of them
}