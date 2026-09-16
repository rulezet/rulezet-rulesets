rule TTP_XOR_MULT_DOSStub_f45e {
  strings:
    $key_f45e = { a0 36 [2] d4 2e [2] 93 2c [2] d4 3d [2] 9a 31 [2] 96 3b [2] 81 30 [2] 9a 7e [2] a7 }

  condition:
    any of them
}