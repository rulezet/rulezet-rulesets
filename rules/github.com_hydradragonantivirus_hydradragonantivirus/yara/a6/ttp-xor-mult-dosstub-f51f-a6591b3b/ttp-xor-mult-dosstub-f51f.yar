rule TTP_XOR_MULT_DOSStub_f51f {
  strings:
    $key_f51f = { a1 77 [2] d5 6f [2] 92 6d [2] d5 7c [2] 9b 70 [2] 97 7a [2] 80 71 [2] 9b 3f [2] a6 }

  condition:
    any of them
}