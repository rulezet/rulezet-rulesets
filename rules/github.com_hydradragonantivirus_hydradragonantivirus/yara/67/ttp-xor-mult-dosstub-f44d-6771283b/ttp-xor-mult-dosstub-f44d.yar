rule TTP_XOR_MULT_DOSStub_f44d {
  strings:
    $key_f44d = { a0 25 [2] d4 3d [2] 93 3f [2] d4 2e [2] 9a 22 [2] 96 28 [2] 81 23 [2] 9a 6d [2] a7 }

  condition:
    any of them
}