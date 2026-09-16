rule TTP_XOR_MULT_DOSStub_e216 {
  strings:
    $key_e216 = { b6 7e [2] c2 66 [2] 85 64 [2] c2 75 [2] 8c 79 [2] 80 73 [2] 97 78 [2] 8c 36 [2] b1 }

  condition:
    any of them
}