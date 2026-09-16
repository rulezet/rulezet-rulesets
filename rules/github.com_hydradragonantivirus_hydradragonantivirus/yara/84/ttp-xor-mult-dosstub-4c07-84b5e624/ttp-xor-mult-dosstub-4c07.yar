rule TTP_XOR_MULT_DOSStub_4c07 {
  strings:
    $key_4c07 = { 18 6f [2] 6c 77 [2] 2b 75 [2] 6c 64 [2] 22 68 [2] 2e 62 [2] 39 69 [2] 22 27 [2] 1f }

  condition:
    any of them
}