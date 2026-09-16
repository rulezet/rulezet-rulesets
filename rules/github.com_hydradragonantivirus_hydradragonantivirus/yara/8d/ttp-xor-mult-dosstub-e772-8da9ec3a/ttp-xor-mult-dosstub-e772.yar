rule TTP_XOR_MULT_DOSStub_e772 {
  strings:
    $key_e772 = { b3 1a [2] c7 02 [2] 80 00 [2] c7 11 [2] 89 1d [2] 85 17 [2] 92 1c [2] 89 52 [2] b4 }

  condition:
    any of them
}