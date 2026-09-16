rule TTP_XOR_MULT_DOSStub_e444 {
  strings:
    $key_e444 = { b0 2c [2] c4 34 [2] 83 36 [2] c4 27 [2] 8a 2b [2] 86 21 [2] 91 2a [2] 8a 64 [2] b7 }

  condition:
    any of them
}