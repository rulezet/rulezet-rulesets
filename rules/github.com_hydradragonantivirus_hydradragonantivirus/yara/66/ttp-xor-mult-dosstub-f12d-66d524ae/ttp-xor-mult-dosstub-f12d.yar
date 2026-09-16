rule TTP_XOR_MULT_DOSStub_f12d {
  strings:
    $key_f12d = { a5 45 [2] d1 5d [2] 96 5f [2] d1 4e [2] 9f 42 [2] 93 48 [2] 84 43 [2] 9f 0d [2] a2 }

  condition:
    any of them
}