rule TTP_XOR_MULT_DOSStub_f47a {
  strings:
    $key_f47a = { a0 12 [2] d4 0a [2] 93 08 [2] d4 19 [2] 9a 15 [2] 96 1f [2] 81 14 [2] 9a 5a [2] a7 }

  condition:
    any of them
}