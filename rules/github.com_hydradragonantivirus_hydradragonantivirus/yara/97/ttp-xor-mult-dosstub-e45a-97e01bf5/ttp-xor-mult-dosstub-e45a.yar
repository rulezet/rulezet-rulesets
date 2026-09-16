rule TTP_XOR_MULT_DOSStub_e45a {
  strings:
    $key_e45a = { b0 32 [2] c4 2a [2] 83 28 [2] c4 39 [2] 8a 35 [2] 86 3f [2] 91 34 [2] 8a 7a [2] b7 }

  condition:
    any of them
}