rule TTP_XOR_MULT_DOSStub_3759 {
  strings:
    $key_3759 = { 63 31 [2] 17 29 [2] 50 2b [2] 17 3a [2] 59 36 [2] 55 3c [2] 42 37 [2] 59 79 [2] 64 }

  condition:
    any of them
}