rule TTP_XOR_MULT_DOSStub_e265 {
  strings:
    $key_e265 = { b6 0d [2] c2 15 [2] 85 17 [2] c2 06 [2] 8c 0a [2] 80 00 [2] 97 0b [2] 8c 45 [2] b1 }

  condition:
    any of them
}