rule TTP_XOR_MULT_DOSStub_f6b3 {
  strings:
    $key_f6b3 = { a2 db [2] d6 c3 [2] 91 c1 [2] d6 d0 [2] 98 dc [2] 94 d6 [2] 83 dd [2] 98 93 [2] a5 }

  condition:
    any of them
}