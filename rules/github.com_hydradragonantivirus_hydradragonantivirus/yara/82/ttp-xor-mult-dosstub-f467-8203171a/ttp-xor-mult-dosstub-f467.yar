rule TTP_XOR_MULT_DOSStub_f467 {
  strings:
    $key_f467 = { a0 0f [2] d4 17 [2] 93 15 [2] d4 04 [2] 9a 08 [2] 96 02 [2] 81 09 [2] 9a 47 [2] a7 }

  condition:
    any of them
}