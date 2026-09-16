rule TTP_XOR_MULT_DOSStub_0b27 {
  strings:
    $key_0b27 = { 5f 4f [2] 2b 57 [2] 6c 55 [2] 2b 44 [2] 65 48 [2] 69 42 [2] 7e 49 [2] 65 07 [2] 58 }

  condition:
    any of them
}