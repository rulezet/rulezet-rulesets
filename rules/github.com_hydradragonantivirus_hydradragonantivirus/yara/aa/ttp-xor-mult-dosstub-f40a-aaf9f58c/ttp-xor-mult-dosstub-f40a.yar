rule TTP_XOR_MULT_DOSStub_f40a {
  strings:
    $key_f40a = { a0 62 [2] d4 7a [2] 93 78 [2] d4 69 [2] 9a 65 [2] 96 6f [2] 81 64 [2] 9a 2a [2] a7 }

  condition:
    any of them
}