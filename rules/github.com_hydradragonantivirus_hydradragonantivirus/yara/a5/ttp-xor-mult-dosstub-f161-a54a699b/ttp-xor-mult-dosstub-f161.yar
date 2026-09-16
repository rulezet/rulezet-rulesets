rule TTP_XOR_MULT_DOSStub_f161 {
  strings:
    $key_f161 = { a5 09 [2] d1 11 [2] 96 13 [2] d1 02 [2] 9f 0e [2] 93 04 [2] 84 0f [2] 9f 41 [2] a2 }

  condition:
    any of them
}