rule TTP_XOR_MULT_DOSStub_e47e {
  strings:
    $key_e47e = { b0 16 [2] c4 0e [2] 83 0c [2] c4 1d [2] 8a 11 [2] 86 1b [2] 91 10 [2] 8a 5e [2] b7 }

  condition:
    any of them
}