rule TTP_XOR_MULT_DOSStub_f46a {
  strings:
    $key_f46a = { a0 02 [2] d4 1a [2] 93 18 [2] d4 09 [2] 9a 05 [2] 96 0f [2] 81 04 [2] 9a 4a [2] a7 }

  condition:
    any of them
}