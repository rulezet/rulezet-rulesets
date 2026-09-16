rule TTP_XOR_MULT_DOSStub_f11f {
  strings:
    $key_f11f = { a5 77 [2] d1 6f [2] 96 6d [2] d1 7c [2] 9f 70 [2] 93 7a [2] 84 71 [2] 9f 3f [2] a2 }

  condition:
    any of them
}