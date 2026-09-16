rule TTP_XOR_MULT_DOSStub_f126 {
  strings:
    $key_f126 = { a5 4e [2] d1 56 [2] 96 54 [2] d1 45 [2] 9f 49 [2] 93 43 [2] 84 48 [2] 9f 06 [2] a2 }

  condition:
    any of them
}