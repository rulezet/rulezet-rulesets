rule TTP_XOR_MULT_DOSStub_e072 {
  strings:
    $key_e072 = { b4 1a [2] c0 02 [2] 87 00 [2] c0 11 [2] 8e 1d [2] 82 17 [2] 95 1c [2] 8e 52 [2] b3 }

  condition:
    any of them
}