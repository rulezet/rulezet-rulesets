rule TTP_XOR_MULT_DOSStub_f120 {
  strings:
    $key_f120 = { a5 48 [2] d1 50 [2] 96 52 [2] d1 43 [2] 9f 4f [2] 93 45 [2] 84 4e [2] 9f 00 [2] a2 }

  condition:
    any of them
}