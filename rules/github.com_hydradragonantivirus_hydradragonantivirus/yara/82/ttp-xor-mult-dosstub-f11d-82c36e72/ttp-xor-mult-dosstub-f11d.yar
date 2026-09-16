rule TTP_XOR_MULT_DOSStub_f11d {
  strings:
    $key_f11d = { a5 75 [2] d1 6d [2] 96 6f [2] d1 7e [2] 9f 72 [2] 93 78 [2] 84 73 [2] 9f 3d [2] a2 }

  condition:
    any of them
}