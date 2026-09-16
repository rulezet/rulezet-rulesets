rule TTP_XOR_MULT_DOSStub_7b60 {
  strings:
    $key_7b60 = { 2f 08 [2] 5b 10 [2] 1c 12 [2] 5b 03 [2] 15 0f [2] 19 05 [2] 0e 0e [2] 15 40 [2] 28 }

  condition:
    any of them
}