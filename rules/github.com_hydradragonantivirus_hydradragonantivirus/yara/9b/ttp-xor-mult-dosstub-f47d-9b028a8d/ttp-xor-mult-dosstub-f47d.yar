rule TTP_XOR_MULT_DOSStub_f47d {
  strings:
    $key_f47d = { a0 15 [2] d4 0d [2] 93 0f [2] d4 1e [2] 9a 12 [2] 96 18 [2] 81 13 [2] 9a 5d [2] a7 }

  condition:
    any of them
}