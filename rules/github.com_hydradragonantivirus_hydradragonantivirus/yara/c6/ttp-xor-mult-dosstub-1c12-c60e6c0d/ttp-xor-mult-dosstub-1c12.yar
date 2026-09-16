rule TTP_XOR_MULT_DOSStub_1c12 {
  strings:
    $key_1c12 = { 48 7a [2] 3c 62 [2] 7b 60 [2] 3c 71 [2] 72 7d [2] 7e 77 [2] 69 7c [2] 72 32 [2] 4f }

  condition:
    any of them
}