rule TTP_XOR_MULT_DOSStub_f131 {
  strings:
    $key_f131 = { a5 59 [2] d1 41 [2] 96 43 [2] d1 52 [2] 9f 5e [2] 93 54 [2] 84 5f [2] 9f 11 [2] a2 }

  condition:
    any of them
}