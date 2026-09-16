rule TTP_XOR_MULT_DOSStub_e245 {
  strings:
    $key_e245 = { b6 2d [2] c2 35 [2] 85 37 [2] c2 26 [2] 8c 2a [2] 80 20 [2] 97 2b [2] 8c 65 [2] b1 }

  condition:
    any of them
}