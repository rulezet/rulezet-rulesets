rule TTP_XOR_MULT_DOSStub_f160 {
  strings:
    $key_f160 = { a5 08 [2] d1 10 [2] 96 12 [2] d1 03 [2] 9f 0f [2] 93 05 [2] 84 0e [2] 9f 40 [2] a2 }

  condition:
    any of them
}