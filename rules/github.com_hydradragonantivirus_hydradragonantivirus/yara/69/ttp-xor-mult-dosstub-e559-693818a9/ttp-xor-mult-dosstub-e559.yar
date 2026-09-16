rule TTP_XOR_MULT_DOSStub_e559 {
  strings:
    $key_e559 = { b1 31 [2] c5 29 [2] 82 2b [2] c5 3a [2] 8b 36 [2] 87 3c [2] 90 37 [2] 8b 79 [2] b6 }

  condition:
    any of them
}