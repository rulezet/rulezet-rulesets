rule TTP_XOR_MULT_DOSStub_e044 {
  strings:
    $key_e044 = { b4 2c [2] c0 34 [2] 87 36 [2] c0 27 [2] 8e 2b [2] 82 21 [2] 95 2a [2] 8e 64 [2] b3 }

  condition:
    any of them
}