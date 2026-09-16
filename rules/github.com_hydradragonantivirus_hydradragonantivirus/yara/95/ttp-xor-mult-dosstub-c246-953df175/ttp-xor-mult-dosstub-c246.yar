rule TTP_XOR_MULT_DOSStub_c246 {
  strings:
    $key_c246 = { 96 2e [2] e2 36 [2] a5 34 [2] e2 25 [2] ac 29 [2] a0 23 [2] b7 28 [2] ac 66 [2] 91 }

  condition:
    any of them
}