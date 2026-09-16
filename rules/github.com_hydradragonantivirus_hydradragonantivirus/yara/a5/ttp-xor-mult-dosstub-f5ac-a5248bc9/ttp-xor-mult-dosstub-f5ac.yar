rule TTP_XOR_MULT_DOSStub_f5ac {
  strings:
    $key_f5ac = { a1 c4 [2] d5 dc [2] 92 de [2] d5 cf [2] 9b c3 [2] 97 c9 [2] 80 c2 [2] 9b 8c [2] a6 }

  condition:
    any of them
}