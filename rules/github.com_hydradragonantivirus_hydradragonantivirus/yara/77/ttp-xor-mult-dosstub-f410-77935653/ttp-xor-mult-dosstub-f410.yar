rule TTP_XOR_MULT_DOSStub_f410 {
  strings:
    $key_f410 = { a0 78 [2] d4 60 [2] 93 62 [2] d4 73 [2] 9a 7f [2] 96 75 [2] 81 7e [2] 9a 30 [2] a7 }

  condition:
    any of them
}