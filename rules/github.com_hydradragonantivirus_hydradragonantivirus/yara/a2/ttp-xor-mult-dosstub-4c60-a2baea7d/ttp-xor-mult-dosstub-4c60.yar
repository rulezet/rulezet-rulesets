rule TTP_XOR_MULT_DOSStub_4c60 {
  strings:
    $key_4c60 = { 18 08 [2] 6c 10 [2] 2b 12 [2] 6c 03 [2] 22 0f [2] 2e 05 [2] 39 0e [2] 22 40 [2] 1f }

  condition:
    any of them
}