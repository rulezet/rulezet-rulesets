rule TTP_XOR_MULT_DOSStub_4c51 {
  strings:
    $key_4c51 = { 18 39 [2] 6c 21 [2] 2b 23 [2] 6c 32 [2] 22 3e [2] 2e 34 [2] 39 3f [2] 22 71 [2] 1f }

  condition:
    any of them
}