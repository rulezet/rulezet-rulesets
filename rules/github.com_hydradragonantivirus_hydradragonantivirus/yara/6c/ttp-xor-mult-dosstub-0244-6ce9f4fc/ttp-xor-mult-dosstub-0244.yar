rule TTP_XOR_MULT_DOSStub_0244 {
  strings:
    $key_0244 = { 56 2c [2] 22 34 [2] 65 36 [2] 22 27 [2] 6c 2b [2] 60 21 [2] 77 2a [2] 6c 64 [2] 51 }

  condition:
    any of them
}