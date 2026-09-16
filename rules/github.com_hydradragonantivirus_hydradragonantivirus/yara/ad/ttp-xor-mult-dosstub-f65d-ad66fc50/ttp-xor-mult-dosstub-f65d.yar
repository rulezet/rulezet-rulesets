rule TTP_XOR_MULT_DOSStub_f65d {
  strings:
    $key_f65d = { a2 35 [2] d6 2d [2] 91 2f [2] d6 3e [2] 98 32 [2] 94 38 [2] 83 33 [2] 98 7d [2] a5 }

  condition:
    any of them
}