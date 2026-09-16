rule TTP_XOR_MULT_DOSStub_e07e {
  strings:
    $key_e07e = { b4 16 [2] c0 0e [2] 87 0c [2] c0 1d [2] 8e 11 [2] 82 1b [2] 95 10 [2] 8e 5e [2] b3 }

  condition:
    any of them
}