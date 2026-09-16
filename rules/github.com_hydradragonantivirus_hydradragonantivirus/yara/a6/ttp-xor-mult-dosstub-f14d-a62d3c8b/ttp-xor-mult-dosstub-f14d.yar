rule TTP_XOR_MULT_DOSStub_f14d {
  strings:
    $key_f14d = { a5 25 [2] d1 3d [2] 96 3f [2] d1 2e [2] 9f 22 [2] 93 28 [2] 84 23 [2] 9f 6d [2] a2 }

  condition:
    any of them
}