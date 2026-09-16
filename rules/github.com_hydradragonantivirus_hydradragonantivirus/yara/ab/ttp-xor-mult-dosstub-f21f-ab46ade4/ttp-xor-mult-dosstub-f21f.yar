rule TTP_XOR_MULT_DOSStub_f21f {
  strings:
    $key_f21f = { a6 77 [2] d2 6f [2] 95 6d [2] d2 7c [2] 9c 70 [2] 90 7a [2] 87 71 [2] 9c 3f [2] a1 }

  condition:
    any of them
}