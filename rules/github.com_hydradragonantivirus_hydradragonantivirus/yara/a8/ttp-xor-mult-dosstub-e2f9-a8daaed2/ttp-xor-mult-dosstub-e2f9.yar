rule TTP_XOR_MULT_DOSStub_e2f9 {
  strings:
    $key_e2f9 = { b6 91 [2] c2 89 [2] 85 8b [2] c2 9a [2] 8c 96 [2] 80 9c [2] 97 97 [2] 8c d9 [2] b1 }

  condition:
    any of them
}