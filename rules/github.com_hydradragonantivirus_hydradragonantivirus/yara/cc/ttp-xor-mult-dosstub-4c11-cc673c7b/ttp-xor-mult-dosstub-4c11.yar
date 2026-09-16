rule TTP_XOR_MULT_DOSStub_4c11 {
  strings:
    $key_4c11 = { 18 79 [2] 6c 61 [2] 2b 63 [2] 6c 72 [2] 22 7e [2] 2e 74 [2] 39 7f [2] 22 31 [2] 1f }

  condition:
    any of them
}