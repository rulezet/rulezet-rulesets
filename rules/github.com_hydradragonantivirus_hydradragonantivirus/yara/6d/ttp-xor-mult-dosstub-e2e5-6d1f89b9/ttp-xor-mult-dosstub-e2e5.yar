rule TTP_XOR_MULT_DOSStub_e2e5 {
  strings:
    $key_e2e5 = { b6 8d [2] c2 95 [2] 85 97 [2] c2 86 [2] 8c 8a [2] 80 80 [2] 97 8b [2] 8c c5 [2] b1 }

  condition:
    any of them
}