rule TTP_XOR_MULT_DOSStub_f135 {
  strings:
    $key_f135 = { a5 5d [2] d1 45 [2] 96 47 [2] d1 56 [2] 9f 5a [2] 93 50 [2] 84 5b [2] 9f 15 [2] a2 }

  condition:
    any of them
}