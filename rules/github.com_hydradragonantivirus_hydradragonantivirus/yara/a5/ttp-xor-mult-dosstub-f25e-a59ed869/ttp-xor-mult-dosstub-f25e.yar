rule TTP_XOR_MULT_DOSStub_f25e {
  strings:
    $key_f25e = { a6 36 [2] d2 2e [2] 95 2c [2] d2 3d [2] 9c 31 [2] 90 3b [2] 87 30 [2] 9c 7e [2] a1 }

  condition:
    any of them
}