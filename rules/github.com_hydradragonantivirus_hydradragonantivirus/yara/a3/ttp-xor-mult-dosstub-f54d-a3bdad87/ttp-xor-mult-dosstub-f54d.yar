rule TTP_XOR_MULT_DOSStub_f54d {
  strings:
    $key_f54d = { a1 25 [2] d5 3d [2] 92 3f [2] d5 2e [2] 9b 22 [2] 97 28 [2] 80 23 [2] 9b 6d [2] a6 }

  condition:
    any of them
}