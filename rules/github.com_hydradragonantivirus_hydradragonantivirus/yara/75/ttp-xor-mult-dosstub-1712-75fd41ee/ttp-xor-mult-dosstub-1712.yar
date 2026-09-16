rule TTP_XOR_MULT_DOSStub_1712 {
  strings:
    $key_1712 = { 43 7a [2] 37 62 [2] 70 60 [2] 37 71 [2] 79 7d [2] 75 77 [2] 62 7c [2] 79 32 [2] 44 }

  condition:
    any of them
}