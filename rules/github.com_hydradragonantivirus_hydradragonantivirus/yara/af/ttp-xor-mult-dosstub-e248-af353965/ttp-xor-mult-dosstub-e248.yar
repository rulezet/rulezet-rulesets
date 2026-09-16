rule TTP_XOR_MULT_DOSStub_e248 {
  strings:
    $key_e248 = { b6 20 [2] c2 38 [2] 85 3a [2] c2 2b [2] 8c 27 [2] 80 2d [2] 97 26 [2] 8c 68 [2] b1 }

  condition:
    any of them
}