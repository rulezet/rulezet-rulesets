rule TTP_XOR_MULT_DOSStub_3c51 {
  strings:
    $key_3c51 = { 68 39 [2] 1c 21 [2] 5b 23 [2] 1c 32 [2] 52 3e [2] 5e 34 [2] 49 3f [2] 52 71 [2] 6f }

  condition:
    any of them
}