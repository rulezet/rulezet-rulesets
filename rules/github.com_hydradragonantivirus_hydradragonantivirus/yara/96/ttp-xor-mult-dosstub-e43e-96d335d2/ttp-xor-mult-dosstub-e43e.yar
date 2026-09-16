rule TTP_XOR_MULT_DOSStub_e43e {
  strings:
    $key_e43e = { b0 56 [2] c4 4e [2] 83 4c [2] c4 5d [2] 8a 51 [2] 86 5b [2] 91 50 [2] 8a 1e [2] b7 }

  condition:
    any of them
}