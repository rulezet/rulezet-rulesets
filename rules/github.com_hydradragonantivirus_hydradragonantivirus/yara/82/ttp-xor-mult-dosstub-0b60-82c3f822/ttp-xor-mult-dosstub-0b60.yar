rule TTP_XOR_MULT_DOSStub_0b60 {
  strings:
    $key_0b60 = { 5f 08 [2] 2b 10 [2] 6c 12 [2] 2b 03 [2] 65 0f [2] 69 05 [2] 7e 0e [2] 65 40 [2] 58 }

  condition:
    any of them
}