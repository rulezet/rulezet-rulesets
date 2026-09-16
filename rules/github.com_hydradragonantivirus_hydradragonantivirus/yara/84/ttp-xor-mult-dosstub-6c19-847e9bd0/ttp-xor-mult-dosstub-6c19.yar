rule TTP_XOR_MULT_DOSStub_6c19 {
  strings:
    $key_6c19 = { 38 71 [2] 4c 69 [2] 0b 6b [2] 4c 7a [2] 02 76 [2] 0e 7c [2] 19 77 [2] 02 39 [2] 3f }

  condition:
    any of them
}