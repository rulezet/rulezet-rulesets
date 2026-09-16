rule TTP_XOR_MULT_DOSStub_3c44 {
  strings:
    $key_3c44 = { 68 2c [2] 1c 34 [2] 5b 36 [2] 1c 27 [2] 52 2b [2] 5e 21 [2] 49 2a [2] 52 64 [2] 6f }

  condition:
    any of them
}