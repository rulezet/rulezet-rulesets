rule TTP_XOR_MULT_DOSStub_4b60 {
  strings:
    $key_4b60 = { 1f 08 [2] 6b 10 [2] 2c 12 [2] 6b 03 [2] 25 0f [2] 29 05 [2] 3e 0e [2] 25 40 [2] 18 }

  condition:
    any of them
}