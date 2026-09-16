rule TTP_XOR_MULT_DOSStub_f4b5 {
  strings:
    $key_f4b5 = { a0 dd [2] d4 c5 [2] 93 c7 [2] d4 d6 [2] 9a da [2] 96 d0 [2] 81 db [2] 9a 95 [2] a7 }

  condition:
    any of them
}