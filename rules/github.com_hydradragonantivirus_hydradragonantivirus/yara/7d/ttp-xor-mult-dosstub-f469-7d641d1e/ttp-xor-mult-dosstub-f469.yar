rule TTP_XOR_MULT_DOSStub_f469 {
  strings:
    $key_f469 = { a0 01 [2] d4 19 [2] 93 1b [2] d4 0a [2] 9a 06 [2] 96 0c [2] 81 07 [2] 9a 49 [2] a7 }

  condition:
    any of them
}