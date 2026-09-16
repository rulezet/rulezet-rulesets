rule TTP_XOR_MULT_DOSStub_f07d {
  strings:
    $key_f07d = { a4 15 [2] d0 0d [2] 97 0f [2] d0 1e [2] 9e 12 [2] 92 18 [2] 85 13 [2] 9e 5d [2] a3 }

  condition:
    any of them
}