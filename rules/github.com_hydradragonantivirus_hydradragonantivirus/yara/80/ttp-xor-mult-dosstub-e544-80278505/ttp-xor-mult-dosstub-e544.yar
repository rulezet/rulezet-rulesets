rule TTP_XOR_MULT_DOSStub_e544 {
  strings:
    $key_e544 = { b1 2c [2] c5 34 [2] 82 36 [2] c5 27 [2] 8b 2b [2] 87 21 [2] 90 2a [2] 8b 64 [2] b6 }

  condition:
    any of them
}