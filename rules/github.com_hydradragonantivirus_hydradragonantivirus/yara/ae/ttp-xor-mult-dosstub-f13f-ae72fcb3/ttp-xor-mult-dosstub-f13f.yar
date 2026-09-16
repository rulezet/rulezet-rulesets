rule TTP_XOR_MULT_DOSStub_f13f {
  strings:
    $key_f13f = { a5 57 [2] d1 4f [2] 96 4d [2] d1 5c [2] 9f 50 [2] 93 5a [2] 84 51 [2] 9f 1f [2] a2 }

  condition:
    any of them
}