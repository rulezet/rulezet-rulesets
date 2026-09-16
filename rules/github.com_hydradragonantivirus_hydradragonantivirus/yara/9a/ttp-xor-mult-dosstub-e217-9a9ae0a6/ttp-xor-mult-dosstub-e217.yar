rule TTP_XOR_MULT_DOSStub_e217 {
  strings:
    $key_e217 = { b6 7f [2] c2 67 [2] 85 65 [2] c2 74 [2] 8c 78 [2] 80 72 [2] 97 79 [2] 8c 37 [2] b1 }

  condition:
    any of them
}