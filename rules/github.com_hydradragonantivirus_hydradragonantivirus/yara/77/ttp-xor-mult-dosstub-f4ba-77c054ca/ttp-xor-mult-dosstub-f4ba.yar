rule TTP_XOR_MULT_DOSStub_f4ba {
  strings:
    $key_f4ba = { a0 d2 [2] d4 ca [2] 93 c8 [2] d4 d9 [2] 9a d5 [2] 96 df [2] 81 d4 [2] 9a 9a [2] a7 }

  condition:
    any of them
}