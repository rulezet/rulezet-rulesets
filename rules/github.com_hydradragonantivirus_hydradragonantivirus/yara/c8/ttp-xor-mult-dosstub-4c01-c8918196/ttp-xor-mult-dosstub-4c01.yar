rule TTP_XOR_MULT_DOSStub_4c01 {
  strings:
    $key_4c01 = { 18 69 [2] 6c 71 [2] 2b 73 [2] 6c 62 [2] 22 6e [2] 2e 64 [2] 39 6f [2] 22 21 [2] 1f }

  condition:
    any of them
}