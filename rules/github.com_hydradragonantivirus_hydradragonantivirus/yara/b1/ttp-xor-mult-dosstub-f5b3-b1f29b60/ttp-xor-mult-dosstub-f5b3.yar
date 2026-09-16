rule TTP_XOR_MULT_DOSStub_f5b3 {
  strings:
    $key_f5b3 = { a1 db [2] d5 c3 [2] 92 c1 [2] d5 d0 [2] 9b dc [2] 97 d6 [2] 80 dd [2] 9b 93 [2] a6 }

  condition:
    any of them
}