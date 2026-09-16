rule TTP_XOR_MULT_DOSStub_f138 {
  strings:
    $key_f138 = { a5 50 [2] d1 48 [2] 96 4a [2] d1 5b [2] 9f 57 [2] 93 5d [2] 84 56 [2] 9f 18 [2] a2 }

  condition:
    any of them
}