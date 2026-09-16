rule TTP_XOR_MULT_DOSStub_f01f {
  strings:
    $key_f01f = { a4 77 [2] d0 6f [2] 97 6d [2] d0 7c [2] 9e 70 [2] 92 7a [2] 85 71 [2] 9e 3f [2] a3 }

  condition:
    any of them
}