rule TTP_XOR_MULT_DOSStub_f164 {
  strings:
    $key_f164 = { a5 0c [2] d1 14 [2] 96 16 [2] d1 07 [2] 9f 0b [2] 93 01 [2] 84 0a [2] 9f 44 [2] a2 }

  condition:
    any of them
}